//! Service proxying: `atproto-proxy: <did>#<service>` (XRPC §Service Proxying).
//!
//! The PDS resolves the service DID, checks the request, mints a short-lived
//! inter-service JWT (`lxm`/`aud`, ES256K, account key), and forwards the
//! request. Only `/xrpc/*` paths are proxied; upstream responses stream back
//! with status preserved.

use axum::{http::{HeaderMap, Method, Uri}, Extension};
use worker::Env;

use crate::{auth, identity, keys, pds_env, repo, xrpc::{XrpcError, XrpcResult}};

/// axum fallback: handles any otherwise-unknown `/xrpc/*` route when the
/// client asks for proxying. Without the header, well-known AppView/Chat
/// NSIDs auto-route to the AppView (the official web client omits the header
/// on some of them); anything else is a plain 404.
/// Env comes from the router [`Extension`] layer (see `lib.rs`).
#[worker::send]
pub async fn proxy_fallback(
    Extension(env): Extension<Env>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> XrpcResult<axum::response::Response> {
    let path = uri.path().to_string();
    if !path.starts_with("/xrpc/") {
        return Err(XrpcError::not_found("NotFound", "unknown endpoint"));
    }
    let lxm = path.strip_prefix("/xrpc/").unwrap_or(&path).to_string();
    let proxy = headers
        .get("atproto-proxy")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| crate::xrpc::parse_proxy_header(Some(v)))
        .or_else(|| {
            // Compat auto-route: AppView/Chat methods for authed local users.
            // Locally-served methods (preferences) are handled by their own
            // routes, which take precedence over this fallback.
            let local = lxm == "app.bsky.actor.getPreferences" || lxm == "app.bsky.actor.putPreferences";
            let app_view = !local && (lxm.starts_with("app.bsky.") || lxm.starts_with("chat.bsky."));
            if app_view {
                if let Ok(cfg) = pds_env::PdsEnv::from_env(&env) {
                    if !cfg.appview_url.is_empty() {
                        return Some((cfg.appview_did.clone(), "bsky_appview".to_string()));
                    }
                }
            }
            None
        })
        .ok_or_else(|| XrpcError::not_found("NotFound", "unknown endpoint (hint: atproto-proxy to reach other services)"))?;
    let (service_did, service_id) = proxy;
    let query = uri.query().unwrap_or("").to_string();

    // Must be an authenticated local user (rate limits still apply at edge).
    let http_method = method.as_str().to_string();
    let caller = auth::authenticate(&env, &headers, http_method.as_str(), path.as_str()).await?;
    crate::ratelimit::check(&env, &format!("proxy:{}", caller.did), 300, 60).await?;

    // Resolve the service endpoint; SSRF-guarded.
    let endpoint = identity::resolve_service(&env, &service_did, &service_id).await?;
    guard_endpoint(&env, &endpoint)?;
    if !crate::atproto::nsid::validate(&lxm) {
        return Err(XrpcError::bad_request("InvalidNsid", "only NSID endpoints can be proxied"));
    }
    if body.len() > 5_000_000 {
        return Err(XrpcError::too_large("proxied body too large"));
    }

    // Inter-service JWT (ES256K, account key, 60s). `aud` is the BARE
    // service DID: verifiers compare exact equality against their own DID
    // (reference `verifyJwt`: `payload.aud !== ownDid` rejects). The
    // `#service` fragment belongs in the `atproto-proxy` header, not here.
    let db = pds_env::db(&env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let priv_hex = repo::signing_key(&db, &caller.did).await?;
    let now = (worker::Date::now().as_millis() / 1000) as i64;
    let jti = keys::random_b64u32().map_err(|e| XrpcError::internal(e.to_string()))?;
    let service_jwt = keys::sign_jwt_es256k(
        &priv_hex,
        &serde_json::json!({
            "iss": caller.did,
            "aud": service_did.clone(),
            "iat": now, "exp": now + 60,
            "lxm": lxm, "jti": jti,
        }),
    )
    .map_err(|e| XrpcError::internal(e.to_string()))?;

    // Forward.
    let mut target = format!("{}{}", endpoint.trim_end_matches('/'), path);
    if !query.is_empty() {
        target.push('?');
        target.push_str(&query);
    }
    let out = forward(&http_method, &target, &headers, body, &service_jwt, &service_did, &service_id).await?;
    Ok(out)
}

fn guard_endpoint(env: &Env, endpoint: &str) -> XrpcResult<()> {
    let deny = || XrpcError::forbidden("ProxyRefused", "service endpoint not allowed");
    let (scheme, rest) = endpoint.split_once("://").ok_or_else(deny)?;
    let host = rest.split('/').next().unwrap_or("");
    let host_only = host.split(':').next().unwrap_or(host);
    let dev = pds_env::PdsEnv::from_env(env)
        .map(|c| c.hostname == "localhost")
        .unwrap_or(false);
    // Loopback targets only in local-dev mode.
    let loopback = host_only == "localhost" || host_only == "127.0.0.1" || host_only == "[::1]" || host_only.ends_with(".localhost");
    if loopback && !dev {
        return Err(deny());
    }
    if !loopback {
        if scheme != "https" {
            return Err(deny());
        }
        // Literal private / metadata IPs.
        let private_ip = host_only.parse::<std::net::IpAddr>().map(|ip| {
            ip.is_loopback()
                || ip.is_unspecified()
                || matches!(ip, std::net::IpAddr::V4(v) if v.is_private() || v.is_link_local() || v.octets()[0] == 169 && v.octets()[1] == 254)
                || matches!(ip, std::net::IpAddr::V6(v) if v.is_unique_local() || v.is_unicast_link_local())
        }).unwrap_or(false);
        if private_ip {
            return Err(deny());
        }
        let h = host_only.to_lowercase();
        if h == "metadata.google.internal" || h.ends_with(".internal") || h.ends_with(".local") {
            return Err(deny());
        }
    } else if scheme != "http" && scheme != "https" {
        return Err(deny());
    }
    Ok(())
}

async fn forward(
    method: &str,
    url: &str,
    headers: &HeaderMap,
    body: axum::body::Bytes,
    service_jwt: &str,
    service_did: &str,
    service_id: &str,
) -> XrpcResult<axum::response::Response> {
    use axum::response::IntoResponse;
    use worker::{Fetch, Method as WMethod, Request, RequestInit};
    let wmethod = match method {
        "GET" => WMethod::Get,
        "POST" => WMethod::Post,
        "PUT" => WMethod::Put,
        "DELETE" => WMethod::Delete,
        "PATCH" => WMethod::Patch,
        "HEAD" => WMethod::Head,
        _ => return Err(XrpcError::bad_request("InvalidRequest", "method not proxied")),
    };
    let mut init = RequestInit::new();
    init.with_method(wmethod);
    if !body.is_empty() {
        let bytes_vec = body.to_vec();
        let js_body: worker::wasm_bindgen::JsValue =
            worker::js_sys::Uint8Array::from(bytes_vec.as_slice()).into();
        init.with_body(Some(js_body));
    }
    let mut req = Request::new_with_init(url, &init).map_err(|e| XrpcError::internal(e.to_string()))?;
    let hdrs = req.headers_mut().map_err(|e| XrpcError::internal(e.to_string()))?;
    if let Some(ct) = headers.get(axum::http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()) {
        let _ = hdrs.set("content-type", ct);
    }
    if let Some(labelers) = headers.get("atproto-accept-labelers").and_then(|v| v.to_str().ok()) {
        let _ = hdrs.set("atproto-accept-labelers", labelers);
    }
    let _ = hdrs.set("authorization", &format!("Bearer {service_jwt}"));
    // Preserve routing info end-to-end: upstreams that gateway by service
    // (e.g. api.bsky.app) need the original proxy target to dispatch.
    let _ = hdrs.set("atproto-proxy", &format!("{service_did}#{service_id}"));
    let mut resp = Fetch::Request(req).send().await.map_err(|e| {
        XrpcError::new(axum::http::StatusCode::BAD_GATEWAY, "ProxyError", format!("upstream unreachable: {e}"))
    })?;
    let status = resp.status_code();
    let ct = resp.headers().get("content-type").ok().flatten().unwrap_or_default();
    let bytes = resp.bytes().await.map_err(|e| XrpcError::internal(e.to_string()))?;
    Ok((
        axum::http::StatusCode::from_u16(status).unwrap_or(axum::http::StatusCode::BAD_GATEWAY),
        [(axum::http::header::CONTENT_TYPE, ct)],
        bytes,
    )
        .into_response())
}

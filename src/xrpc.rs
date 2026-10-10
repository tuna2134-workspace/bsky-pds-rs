//! XRPC helpers: https://atproto.com/specs/xrpc
//! Standard error envelope `{"error":"...","message":"..."}` + status mapping.

use axum::{http::StatusCode, response::{IntoResponse, Response}, Json};
use serde_json::json;

#[derive(Debug)]
pub struct XrpcError {
    pub status: StatusCode,
    pub error: &'static str,
    pub message: String,
}

impl XrpcError {
    pub fn new(status: StatusCode, error: &'static str, message: impl Into<String>) -> Self {
        Self { status, error, message: message.into() }
    }
    pub fn bad_request(error: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, error, message)
    }
    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "AuthenticationRequired", message)
    }
    pub fn forbidden(error: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, error, message)
    }
    pub fn not_found(error: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, error, message)
    }
    pub fn too_large(message: impl Into<String>) -> Self {
        Self::new(StatusCode::PAYLOAD_TOO_LARGE, "PayloadTooLarge", message)
    }
    pub fn rate_limited(message: impl Into<String>) -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, "RateLimitExceeded", message)
    }
    pub fn not_implemented(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_IMPLEMENTED, "NotImplemented", message)
    }
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "InternalError", message)
    }
}

impl IntoResponse for XrpcError {
    fn into_response(self) -> Response {
        let body = Json(json!({ "error": self.error, "message": self.message }));
        (self.status, body).into_response()
    }
}

pub type XrpcResult<T> = Result<T, XrpcError>;

/// Parse `atproto-proxy: <did>#<service>` header per XRPC service-proxying spec.
pub fn parse_proxy_header(value: Option<&str>) -> Option<(String, String)> {
    let v = value?;
    let (did, service) = v.split_once('#')?;
    if did.is_empty() || service.is_empty() {
        return None;
    }
    Some((did.to_string(), service.to_string()))
}

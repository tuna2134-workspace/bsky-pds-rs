// TEMPORARY: live-data regression probe (removed before commit).
#[cfg(test)]
mod live_probe {
    #[test]
    fn live_plc_op() {
        let op: serde_json::Value = serde_json::from_str(r#"{"type":"plc_operation","rotationKeys":["did:key:zQ3shhCGUqDKjStzuDxPkTxN6ujddP4RkEKJJouJGRRkaLGbg","did:key:zQ3shpKnbdPx3g3CmPf5cRVTPe1HtSwVn5ish3wSnDPQCbLJK"],"verificationMethods":{"atproto":"did:key:zQ3shQo6TF2moaqMTrUZEM1jeuYRQXeHEx4evX9751y2qPqRA"},"alsoKnownAs":["at://bsky.app"],"services":{"atproto_pds":{"type":"AtprotoPersonalDataServer","endpoint":"https://puffball.us-east.host.bsky.network"}},"prev":"bafyreiexwziulimyiw3qlhpwr2zljk5jtzdp2bgqbgoxuemjsf5a6tan3a","sig":"8Wj9Cf74dZFNKx7oucZSHbBDFOMJ3xx9lkvj5rT9xMErssWYl1D9n4PeGC0mNml7xDG7uoQqZ1JWoApGADUgXg"}"#).unwrap();
        let mut unsigned = op.clone();
        unsigned.as_object_mut().unwrap().remove("sig");
        let bytes = crate::cbor::encode_json(&unsigned).unwrap();
        eprintln!("UNSIGNED: {}", hex::encode(&bytes));
        let digest = crate::keys::sha256_of(&bytes);
        use base64::Engine as _;
        let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(op["sig"].as_str().unwrap()).unwrap();
        let rot_pub = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        // derive actual pub from did:key instead:
        let rk = "did:key:zQ3shhCGUqDKjStzuDxPkTxN6ujddP4RkEKJJouJGRRkaLGbg";
        let body = &rk["did:key:z".len()..];
        let raw = bs58::decode(body).with_alphabet(bs58::Alphabet::BITCOIN).into_vec().unwrap();
        assert_eq!(&raw[..2], &[0xe7, 0x01]);
        let pub_hex = hex::encode(&raw[2..]);
        eprintln!("PUB: {pub_hex}");
        assert_eq!(pub_hex.len(), 66);
        let _ = rot_pub;
        match crate::keys::verify_digest(&pub_hex, &digest, &sig) {
            Ok(()) => eprintln!("RUST VERIFY: VALID"),
            Err(e) => eprintln!("RUST VERIFY: INVALID ({e})"),
        }
    }
}

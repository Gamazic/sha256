use sha256::sha256hex;

#[test]
fn test_sha256hex_short() {
    let input = "hello";
    let expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

    assert_eq!(sha256hex(input.as_bytes()), expected);
}

#[test]
fn test_sha256hex_long() {
    let input = "dfsajn;jdsbf;jasbd;fhadsofh ;aodhfpoiasdhfoihads;oifha osihfioahsd[fihasoifhoih284hfuosdf";
    let expected = "32ece4752ab2bc4955461477c8654decc4b31a96b9b051718255cbaf7a6cd0a8";

    assert_eq!(sha256hex(input.as_bytes()), expected);
}

#[test]
fn test_sha256hex_unicode() {
    let input = "далеко";
    let expected = "2f3268a2655dbcd8217442c491f579ad8a5d32d95f3dd9847ff197749b2cc88e";

    assert_eq!(sha256hex(input.as_bytes()), expected);
}
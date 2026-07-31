//! Minimal hand-rolled DER reader, just deep enough to pull the
//! `subjectAltName` extension's `dNSName` entries out of an X.509
//! certificate. Not a general ASN.1/X.509 library — it only understands
//! the small slice of the grammar needed to walk
//! `Certificate -> TBSCertificate -> Extensions -> SubjectAltName`.

/// OID 2.5.29.17 (subjectAltName), DER-encoded value bytes.
const SAN_OID: [u8; 3] = [0x55, 0x1D, 0x11];

/// A single DER tag-length-value.
struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
}

/// Read one TLV off the front of `data`, returning it plus whatever
/// follows. Supports short-form and multi-byte long-form lengths.
fn read_tlv(data: &[u8]) -> Option<(Tlv<'_>, &[u8])> {
    if data.len() < 2 {
        return None;
    }
    let tag = data[0];
    let len_byte = data[1];
    let mut pos = 2;

    let len = if len_byte & 0x80 == 0 {
        len_byte as usize
    } else {
        let n = (len_byte & 0x7F) as usize;
        if n == 0 || n > 4 || data.len() < pos + n {
            return None;
        }
        let mut len = 0usize;
        for &b in &data[pos..pos + n] {
            len = (len << 8) | b as usize;
        }
        pos += n;
        len
    };

    if data.len() < pos + len {
        return None;
    }
    Some((Tlv { tag, value: &data[pos..pos + len] }, &data[pos + len..]))
}

/// Iterate every top-level TLV inside `data` (i.e. the children of
/// whatever SEQUENCE/SET this slice is the content of).
fn iter_tlvs(mut data: &[u8]) -> impl Iterator<Item = Tlv<'_>> {
    std::iter::from_fn(move || {
        if data.is_empty() {
            return None;
        }
        let (tlv, rest) = read_tlv(data)?;
        data = rest;
        Some(tlv)
    })
}

/// Extract every `dNSName` GeneralName from a DER-encoded certificate's
/// `subjectAltName` extension. Returns an empty vec if the certificate is
/// malformed or has no SAN extension, rather than erroring — a live cert
/// grab is a best-effort source, not something worth failing the plugin
/// stage over.
pub fn extract_san_dns_names(cert_der: &[u8]) -> Vec<String> {
    let mut names = Vec::new();

    let Some((cert_seq, _)) = read_tlv(cert_der) else { return names };
    if cert_seq.tag != 0x30 {
        return names;
    }
    let Some((tbs, _)) = read_tlv(cert_seq.value) else { return names };
    if tbs.tag != 0x30 {
        return names;
    }

    // Extensions is `[3] EXPLICIT SEQUENCE OF Extension`, the only
    // context-constructed tag 3 child at the top of TBSCertificate.
    let Some(extensions_wrapper) = iter_tlvs(tbs.value).find(|c| c.tag == 0xA3) else {
        return names;
    };
    let Some((ext_seq, _)) = read_tlv(extensions_wrapper.value) else { return names };
    if ext_seq.tag != 0x30 {
        return names;
    }

    for extension in iter_tlvs(ext_seq.value) {
        if extension.tag != 0x30 {
            continue;
        }
        let mut fields = iter_tlvs(extension.value);
        let Some(oid) = fields.next() else { continue };
        if oid.tag != 0x06 || oid.value != SAN_OID {
            continue;
        }

        // Optional `critical BOOLEAN DEFAULT FALSE` sits between the OID
        // and the OCTET STRING payload.
        let mut next = fields.next();
        if matches!(&next, Some(f) if f.tag == 0x01) {
            next = fields.next();
        }
        let Some(octet_string) = next else { continue };
        if octet_string.tag != 0x04 {
            continue;
        }

        let Some((general_names, _)) = read_tlv(octet_string.value) else { continue };
        if general_names.tag != 0x30 {
            continue;
        }

        for name in iter_tlvs(general_names.value) {
            // GeneralName ::= CHOICE, dNSName is `[2] IA5String` — context
            // class, primitive, tag number 2 -> 0x82.
            if name.tag == 0x82 {
                if let Ok(s) = std::str::from_utf8(name.value) {
                    names.push(s.to_string());
                }
            }
        }
    }

    names
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        assert!(value.len() < 128, "test helper only supports short-form lengths");
        out.push(value.len() as u8);
        out.extend_from_slice(value);
        out
    }

    fn build_test_cert(dns_names: &[&str]) -> Vec<u8> {
        let general_names: Vec<u8> =
            dns_names.iter().flat_map(|n| tlv(0x82, n.as_bytes())).collect();
        let san_octet_string = tlv(0x04, &tlv(0x30, &general_names));

        let mut extension_body = tlv(0x06, &SAN_OID);
        extension_body.extend(san_octet_string);
        let extension = tlv(0x30, &extension_body);

        let extensions_seq = tlv(0x30, &extension);
        let extensions_wrapper = tlv(0xA3, &extensions_seq);

        // A handful of dummy TBSCertificate fields ahead of Extensions,
        // to prove the parser skips unrelated siblings correctly.
        let serial = tlv(0x02, &[0x01]);
        let signature_alg = tlv(0x30, &[]);
        let issuer = tlv(0x30, &[]);
        let validity = tlv(0x30, &[]);
        let subject = tlv(0x30, &[]);
        let spki = tlv(0x30, &[]);

        let mut tbs_body = Vec::new();
        tbs_body.extend(serial);
        tbs_body.extend(signature_alg);
        tbs_body.extend(issuer);
        tbs_body.extend(validity);
        tbs_body.extend(subject);
        tbs_body.extend(spki);
        tbs_body.extend(extensions_wrapper);

        let tbs = tlv(0x30, &tbs_body);
        tlv(0x30, &tbs)
    }

    #[test]
    fn extracts_multiple_dns_names() {
        let cert = build_test_cert(&["example.com", "www.example.com"]);
        let names = extract_san_dns_names(&cert);
        assert_eq!(names, vec!["example.com".to_string(), "www.example.com".to_string()]);
    }

    #[test]
    fn returns_empty_for_no_san_extension() {
        let tbs = tlv(0x30, &tlv(0x02, &[0x01]));
        let cert = tlv(0x30, &tbs);
        assert!(extract_san_dns_names(&cert).is_empty());
    }

    #[test]
    fn returns_empty_for_garbage_input() {
        assert!(extract_san_dns_names(&[0xFF, 0x01]).is_empty());
        assert!(extract_san_dns_names(&[]).is_empty());
    }
}

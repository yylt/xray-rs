use super::*;
use serde_json::json;

#[test]
fn endpoint_resolution_and_authority() {
    for (name, security, upload, download, outbound, expected) in [
        (
            "separate domains override global TLS name",
            "tls",
            json!({"address": "upload.example", "port": 8443}),
            json!({"address": "download.example", "port": 9443}),
            None,
            [Some(("upload.example", 8443)), Some(("download.example", 9443))],
        ),
        (
            "omitted addresses use TLS name before outbound",
            "tls",
            json!({"port": 8443}),
            json!({"port": 9443}),
            Some("outbound.example"),
            [Some(("global.example", 8443)), Some(("global.example", 9443))],
        ),
        (
            "omitted upload uses TLS name and preserves outbound port",
            "tls",
            json!(null),
            json!(null),
            Some("outbound.example"),
            [Some(("global.example", 1234)), Some(("global.example", 1234))],
        ),
        (
            "omitted download inherits explicit upload despite TLS and outbound",
            "tls",
            json!({"address": "upload.example", "port": 8443}),
            json!(null),
            Some("outbound.example"),
            [Some(("upload.example", 8443)), Some(("upload.example", 8443))],
        ),
        (
            "explicit download prefers TLS name over upload inheritance",
            "tls",
            json!({"address": "upload.example", "port": 8443}),
            json!({"port": 9443}),
            None,
            [Some(("upload.example", 8443)), Some(("global.example", 9443))],
        ),
        (
            "without TLS explicit download prefers outbound over upload",
            "none",
            json!({"address": "upload.example", "port": 8443}),
            json!({"port": 9443}),
            Some("outbound.example"),
            [Some(("upload.example", 8443)), Some(("outbound.example", 9443))],
        ),
        (
            "without TLS or outbound explicit download inherits upload name only",
            "none",
            json!({"address": "upload.example", "port": 8443}),
            json!({"port": 9443}),
            None,
            [Some(("upload.example", 8443)), Some(("upload.example", 9443))],
        ),
        (
            "without TLS omitted upload ignores serverName and uses outbound",
            "none",
            json!(null),
            json!(null),
            Some("outbound.example"),
            [Some(("outbound.example", 1234)), Some(("outbound.example", 1234))],
        ),
        (
            "explicit IPv4 and IPv6 override global TLS name",
            "tls",
            json!({"address": "192.0.2.1", "port": 8443}),
            json!({"address": "2001:db8::1", "port": 9443}),
            Some("outbound.example"),
            [Some(("192.0.2.1", 8443)), Some(("2001:db8::1", 9443))],
        ),
        (
            "listener without remote endpoints is permitted",
            "none",
            json!(null),
            json!(null),
            None,
            [None, None],
        ),
        (
            "TLS name alone does not invent an upload port",
            "tls",
            json!(null),
            json!(null),
            None,
            [None, None],
        ),
    ] {
        let settings: StreamSettings = serde_json::from_value(json!({
            "network": "xhttp", "security": security,
            "tlsSettings": {"serverName": "global.example", "alpn": ["h2"]},
            "xhttpSettings": {"path": "/test", "upload": upload, "download": download}
        }))
        .unwrap();
        let server = outbound.map(|address| Address::Domain(address.to_owned(), 1234));
        let transport = Xhttp::new(&settings, server, Arc::new(DnsResolver)).unwrap();
        for (endpoint, expected) in [transport.settings.upload.as_ref(), transport.settings.download.as_ref()]
            .into_iter()
            .zip(expected)
        {
            assert_eq!(endpoint.map(|e| (e.address.as_str(), e.port)), expected, "{name}");
            if let Some((address, port)) = expected {
                let host = if address.contains(':') {
                    format!("[{address}]")
                } else {
                    address.to_owned()
                };
                let uri = transport.request_uri(endpoint, "/test/id").unwrap();
                assert_eq!(uri.authority().unwrap().as_str(), format!("{host}:{port}"), "{name}");
                assert_eq!(
                    uri.scheme_str(),
                    Some(if security == "tls" { "https" } else { "http" }),
                    "{name}"
                );
            }
        }
    }
}

#[test]
fn invalid_endpoint_addresses_are_rejected() {
    for endpoint in ["upload", "download"] {
        for address in ["", " ", "\t\n"] {
            let mut value = json!({"network": "xhttp", "xhttpSettings": {"path": "/test"}});
            value["xhttpSettings"][endpoint] = json!({"address": address, "port": 8443});
            let error = serde_json::from_value::<StreamSettings>(value).unwrap_err();
            assert!(error.to_string().contains("address must not be empty"), "{endpoint}: {error}");
        }
        let mut value = json!({
            "network": "xhttp", "security": "none",
            "tlsSettings": {"serverName": "ignored.example"},
            "xhttpSettings": {"path": "/test"}
        });
        value["xhttpSettings"][endpoint] = json!({"port": 8443});
        let settings: StreamSettings = serde_json::from_value(value).unwrap();
        let error = Xhttp::new(&settings, None, Arc::new(DnsResolver)).err().unwrap();
        assert_eq!(error.kind(), ErrorKind::InvalidInput, "{endpoint}: {error}");
        assert!(error.to_string().contains("endpoint address missing"), "{endpoint}: {error}");
    }
}

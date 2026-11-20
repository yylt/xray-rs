use super::*;

#[tokio::test]
async fn metrics_routes_without_token_and_retention_validation() {
    assert_eq!(serde_json::from_str::<InSetting>("{}").unwrap().retention, "24h");
    assert_eq!(
        serde_json::from_str::<InSetting>(r#"{"token":"secret"}"#)
            .unwrap()
            .token
            .as_deref(),
        Some("secret")
    );
    let stats = crate::common::stats::create_shared_stats();
    let router = Arc::new(tokio::sync::RwLock::new(crate::route::Router::new()));
    let sinks = Arc::new(std::collections::HashMap::new());
    assert!(metrics::duration("4d").is_err());
    for (path, expected, content) in [
        ("/", "200 OK", "Management"),
        ("/api/v1/metrics", "200 OK", "# TYPE xray_traffic_bytes_total counter"),
        ("/api/v1/metrics/history?range=1h", "200 OK", "retention_seconds"),
        ("/api/v1/metrics/history?range=3d", "400 Bad Request", "invalid range"),
        ("/api/v1/metrics/history?range=0h", "400 Bad Request", "invalid range"),
        ("/missing", "404 Not Found", "not found"),
    ] {
        let (tx, _rx) = tokio::sync::watch::channel(false);
        let management = ManagementState::new("config.yaml".into(), None, tx, Arc::new(crate::route::DnsResolver));
        let api = ApiInbound::new(
            &InSetting::default(),
            stats.clone(),
            router.clone(),
            sinks.clone(),
            management.clone(),
        )
        .unwrap();
        let (mut client, server) = tokio::io::duplex(128 * 1024);
        let stats = stats.clone();
        let router = router.clone();
        let sinks = sinks.clone();
        let task = tokio::spawn(async move {
            http1::Builder::new()
                .serve_connection(
                    hyper_util::rt::TokioIo::new(server),
                    service_fn(move |req| {
                        handle_request(
                            req,
                            api.history.clone(),
                            stats.clone(),
                            router.clone(),
                            sinks.clone(),
                            management.clone(),
                        )
                    }),
                )
                .await
                .unwrap();
        });
        client
            .write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).await.unwrap();
        task.await.unwrap();
        assert!(response.contains(expected), "{path}: {response}");
        assert!(response.contains(content), "{path}");
    }
}

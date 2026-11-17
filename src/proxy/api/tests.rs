use super::*;

#[tokio::test]
async fn metrics_routes_without_token_and_retention_validation() {
    assert_eq!(serde_json::from_str::<InSetting>("{}").unwrap().retention, "24h");
    assert!(serde_json::from_str::<InSetting>(r#"{"token":"removed"}"#).is_err());
    let stats = crate::common::stats::create_shared_stats();
    let router = Arc::new(tokio::sync::RwLock::new(crate::route::Router::new()));
    let sinks = Arc::new(std::collections::HashMap::new());
    assert!(ApiInbound::new(
        &InSetting { retention: "4d".into() },
        stats.clone(),
        router.clone(),
        sinks.clone()
    )
    .is_err());
    for (path, expected, content) in [
        ("/", "200 OK", "<canvas"),
        ("/metrics", "200 OK", "# TYPE xray_traffic_bytes_total counter"),
        ("/metrics/history?range=1h", "200 OK", "retention_seconds"),
        ("/metrics/history?range=3d", "400 Bad Request", "invalid range"),
        ("/metrics/history?range=0h", "400 Bad Request", "invalid range"),
        ("/missing", "404 Not Found", "not found"),
    ] {
        let api = ApiInbound::new(&InSetting::default(), stats.clone(), router.clone(), sinks.clone()).unwrap();
        let (mut client, server) = tokio::io::duplex(128 * 1024);
        let stats = stats.clone();
        let router = router.clone();
        let sinks = sinks.clone();
        let task = tokio::spawn(async move {
            http1::Builder::new()
                .serve_connection(
                    hyper_util::rt::TokioIo::new(server),
                    service_fn(move |req| {
                        handle_request(req, api.history.clone(), stats.clone(), router.clone(), sinks.clone())
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

use super::*;

#[test]
fn persistence_selection_does_not_persist_request_bearers() {
    let client = Client::new("https://example.com").unwrap();
    let disabled = client.with_persist(Persist::Disabled).unwrap();
    assert!(matches!(disabled.persist, Some(Persist::Disabled)));
    assert!(client.persist.is_none());
    let scope = device::Scope {
        app: "test-app".into(),
        origin: "https://example.com".into(),
        project: "test-project".into(),
    };
    assert!(disabled.device_store(scope).unwrap().is_none());
    let token = "a".repeat(43);
    let request = client.with_bearer(&token).unwrap();
    assert!(matches!(request.persist, Some(Persist::Disabled)));
}

#[test]
fn clones_share_the_bound_device_and_explicit_bearers_bypass_it() {
    let path = std::env::current_dir()
        .unwrap()
        .join(std::env::var_os("CARGO_TARGET_DIR").unwrap_or_else(|| "target".into()))
        .join("test-home")
        .join(format!("client-device-{}", std::process::id()));
    let client = Client::new("https://example.com")
        .unwrap()
        .with_persist(Persist::Dir(path.clone()))
        .unwrap();
    let scope = device::Scope {
        app: "test-app".into(),
        origin: "https://example.com".into(),
        project: "test-project".into(),
    };
    let open = device::Device::open;
    let first = client
        .device_store_with(scope.clone(), open)
        .unwrap()
        .unwrap();
    let second = client
        .clone()
        .device_store_with(scope.clone(), open)
        .unwrap()
        .unwrap();
    assert!(Arc::ptr_eq(&first, &second));
    let request = client.with_bearer(&"a".repeat(43)).unwrap();
    assert!(request.device_store(scope).unwrap().is_none());
    let credentials = SessionCredentials {
        access_token: "a".repeat(43),
        refresh_token: "b".repeat(43),
        expires_at: "2100-01-01T00:00:00Z".into(),
        refresh_expires_at: "2100-01-02T00:00:00Z".into(),
        user_id: "00000000-0000-4000-8000-000000000001".into(),
        session_id: "00000000-0000-4000-8000-000000000002".into(),
    };
    let custom =
        Arc::new(MemorySessionStore::new("https://example.com", Some(credentials)).unwrap());
    let custom_client = client.with_session(custom.clone()).unwrap();
    assert!(custom_client.session.is_some());
    assert!(matches!(custom_client.persist, Some(Persist::Disabled)));
    let device_client = custom_client
        .with_persist(Persist::Dir(path.clone()))
        .unwrap();
    assert!(device_client.session.is_none() && device_client.bearer.is_none());
    let custom_again = device_client.with_session(custom).unwrap();
    assert!(custom_again.session.is_some());
    assert!(matches!(custom_again.persist, Some(Persist::Disabled)));
    drop((
        first,
        second,
        request,
        client,
        custom_client,
        device_client,
        custom_again,
    ));
    std::fs::write(
        path.with_extension("cleanup.txt"),
        path.as_os_str().as_encoded_bytes(),
    )
    .unwrap();
    std::fs::remove_dir_all(path).unwrap();
}

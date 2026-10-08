use std::collections::HashMap;

use crate::Manifest;

fn manifest(routes: &str) -> Result<Manifest, crate::ManifestError> {
    Manifest::parse(format!(r#"{{"schemaVersion":1,"routes":[{routes}]}}"#).as_bytes())
}

#[test]
fn the_bundled_manifest_parses() {
    assert!(!Manifest::bundled().routes.is_empty());
}

#[test]
fn unknown_credentials_and_effects_are_refused_whole() {
    let ok = r#"{"method":"GET","path":"/a","credential":"access"}"#;
    for bad in [
        r#"{"method":"GET","path":"/b","credential":"superuser"}"#,
        r#"{"method":"GET","path":"/b","credential":"access","issues":"everything"}"#,
        r#"{"method":"GET","path":"/b","credential":"access","clears":["session"]}"#,
        r#"{"method":"TRACE","path":"/b","credential":"access"}"#,
        r#"{"method":"GET","path":"b","credential":"access"}"#,
    ] {
        assert!(manifest(&format!("{ok},{bad}")).is_err(), "{bad}");
    }
    assert!(Manifest::parse(br#"{"schemaVersion":2,"routes":[]}"#).is_err());
    assert!(manifest(ok).is_ok());
    assert!(manifest(r#"{"method":"GET","path":"/b","credential":"access","issues":""}"#).is_ok());
}

#[test]
fn a_static_segment_beats_a_parameter() {
    let m = manifest(
        r#"{"method":"POST","path":"/admin/users/{userId}","credential":"access"},
           {"method":"POST","path":"/admin/users/import","credential":"access","issues":"access"}"#,
    )
    .unwrap();
    assert_eq!(
        m.find("POST", "/admin/users/import").unwrap().route.path,
        "/admin/users/import"
    );
    assert_eq!(
        m.find("POST", "/admin/users/IMPORT").unwrap().route.path,
        "/admin/users/import"
    );
    let found = m.find("post", "/admin/users/u-1").unwrap();
    assert_eq!(found.route.path, "/admin/users/{userId}");
    assert_eq!(found.params["userId"], "u-1");
    assert!(m.find("GET", "/admin/users/import").is_none());
    assert!(m.find("POST", "/admin/users").is_none());
}

#[test]
fn dot_and_malformed_parameters_are_refused() {
    let m = manifest(r#"{"method":"GET","path":"/sessions/{id}","credential":"access"}"#).unwrap();
    for path in [
        "/sessions/..",
        "/sessions/.",
        "/sessions/%2e%2E",
        "/sessions/%2E",
        "/sessions/%",
        "/sessions/%ff",
        "/sessions/%+1",
    ] {
        assert!(m.find("GET", path).is_none(), "{path}");
    }
}

#[test]
fn parameters_are_re_escaped() {
    let m = manifest(r#"{"method":"GET","path":"/sessions/{id}","credential":"access"}"#).unwrap();
    let route = &m.routes[0];
    let params = |v: &str| HashMap::from([("id".to_string(), v.to_string())]);
    assert_eq!(route.upstream_path(&params("a b")), "/sessions/a%20b");
    assert_eq!(
        route.upstream_path(&params("../x?y#z")),
        "/sessions/..%2Fx%3Fy%23z"
    );
    assert_eq!(
        route.upstream_path(&params("a@b.test")),
        "/sessions/a@b.test"
    );
}

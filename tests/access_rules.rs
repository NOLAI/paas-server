use chrono::Utc;
use libpep::core::transcryption::PseudonymizationDomain;
use paas_server::access_rules::{AccessRules, Permission};
use paas_server::auth::core::AuthInfo;

#[test]
fn test_access_rules_integration() {
    let user = AuthInfo {
        username: "test_user".to_string(),
        groups: vec!["group1".to_string()],
    };

    let permission = Permission {
        usergroups: vec!["group1".to_string()],
        start: Some(Utc::now() - chrono::Duration::hours(1)),
        end: Some(Utc::now() + chrono::Duration::hours(1)),
        from: vec![PseudonymizationDomain::from("domain1")],
        to: vec![PseudonymizationDomain::from("domain2")],
    };

    let access_rules = AccessRules {
        allow: vec![permission],
    };

    assert!(access_rules.has_access(
        &user,
        &PseudonymizationDomain::from("domain1"),
        &PseudonymizationDomain::from("domain2")
    ));
}

#[test]
fn test_access_rules_edge_cases() {
    let user_with_valid_group = AuthInfo {
        username: "valid_user".to_string(),
        groups: vec!["group1".to_string()],
    };

    let user_with_invalid_group = AuthInfo {
        username: "invalid_user".to_string(),
        groups: vec!["group2".to_string()],
    };

    let permission = Permission {
        usergroups: vec!["group1".to_string()],
        start: Some(Utc::now() - chrono::Duration::hours(1)),
        end: Some(Utc::now() + chrono::Duration::hours(1)),
        from: vec![PseudonymizationDomain::from("domain1")],
        to: vec![PseudonymizationDomain::from("domain2")],
    };

    let access_rules = AccessRules {
        allow: vec![permission],
    };

    // Test valid user with valid time and domains
    assert!(access_rules.has_access(
        &user_with_valid_group,
        &PseudonymizationDomain::from("domain1"),
        &PseudonymizationDomain::from("domain2")
    ));

    // Test valid user with valid group but outside valid time range
    let permission_outside_time = Permission {
        usergroups: vec!["group1".to_string()],
        start: Some(Utc::now() + chrono::Duration::hours(1)),
        end: Some(Utc::now() + chrono::Duration::hours(2)),
        from: vec![PseudonymizationDomain::from("domain1")],
        to: vec![PseudonymizationDomain::from("domain2")],
    };

    let access_rules_outside_time = AccessRules {
        allow: vec![permission_outside_time],
    };

    assert!(!access_rules_outside_time.has_access(
        &user_with_valid_group,
        &PseudonymizationDomain::from("domain1"),
        &PseudonymizationDomain::from("domain2")
    ));

    // Test user with invalid group
    assert!(!access_rules.has_access(
        &user_with_invalid_group,
        &PseudonymizationDomain::from("domain1"),
        &PseudonymizationDomain::from("domain2")
    ));

    // Test valid user with valid group and time but incorrect domains
    assert!(!access_rules.has_access(
        &user_with_valid_group,
        &PseudonymizationDomain::from("domain3"),
        &PseudonymizationDomain::from("domain4")
    ));
}

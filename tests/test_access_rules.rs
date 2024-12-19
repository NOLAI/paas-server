use chrono::Utc;
use libpep::high_level::contexts::PseudonymizationContext;
use paas_server::access_rules::{AccessRules, AuthenticatedUser, Permission};
use std::collections::HashSet;
use std::sync::Arc;

#[test]
fn test_access_rules_integration() {
    let user = AuthenticatedUser {
        username: Arc::new("test_user".to_string()),
        usergroups: Arc::new(HashSet::from(["group1".to_string()])),
    };

    let permission = Permission {
        usergroups: vec!["group1".to_string()],
        start: Some(Utc::now() - chrono::Duration::hours(1)),
        end: Some(Utc::now() + chrono::Duration::hours(1)),
        from: vec![PseudonymizationContext::from("context1")],
        to: vec![PseudonymizationContext::from("context2")],
    };

    let access_rules = AccessRules {
        allow: vec![permission],
    };

    assert!(access_rules.has_access(
        &user,
        &PseudonymizationContext::from("context1"),
        &PseudonymizationContext::from("context2")
    ));
}

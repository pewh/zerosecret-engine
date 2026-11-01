#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crate::{Connection, GrantRule, Materialization, Policy, ResourcePolicy};

pub(crate) fn policy() -> Policy {
    serde_json::from_str(
        r#"{
        "version": 1,
        "resources": [
            {"name": "stripe-production", "host": "api.stripe.com", "protocol": "https",
             "operations": ["GET", "POST"], "materialization": "retrieve"}
        ],
        "grants": [
            {"subject": "alice@company.com", "workload": "claude-code",
             "resource": "stripe-production", "operations": ["GET"], "environment": "development"}
        ]}"#,
    )
    .unwrap()
}

pub(crate) fn any_method_policy() -> Policy {
    serde_json::from_str(
        r#"{
        "version": 1,
        "resources": [
            {"name": "any-api", "host": "api.example.com", "protocol": "https",
             "operations": ["*"], "materialization": "retrieve"},
            {"name": "orders-pg", "host": "db.example.com", "protocol": "postgres",
             "operations": ["*"], "materialization": "retrieve"}
        ],
        "grants": [
            {"subject": "alice@company.com", "workload": "claude-code",
             "resource": "any-api", "operations": ["*"], "environment": "development"},
            {"subject": "alice@company.com", "workload": "claude-code",
             "resource": "orders-pg", "operations": ["*"], "environment": "development"}
        ]}"#,
    )
    .unwrap()
}

pub(crate) fn projected_policy() -> Policy {
    serde_json::from_str(
        r#"{
        "version": 1,
        "resources": [
            {"name": "billing-api", "project": "billing", "host": "api.billing.test",
             "protocol": "https", "operations": ["GET"], "materialization": "retrieve"},
            {"name": "shared-api", "host": "api.shared.test",
             "protocol": "https", "operations": ["GET"], "materialization": "retrieve"}
        ],
        "grants": [
            {"subject": "alice@acme.test", "workload": "claude-code",
             "resource": "billing-api", "operations": ["GET"], "environment": "development"},
            {"subject": "alice@acme.test", "workload": "claude-code",
             "resource": "shared-api", "operations": ["GET"], "environment": "development"}
        ]}"#,
    )
    .unwrap()
}

pub(crate) fn grid_policy() -> Policy {
    serde_json::from_str(
        r#"{
        "version": 1,
        "resources": [
            {"name": "billing-api", "project": "billing", "host": "api.billing.test",
             "protocol": "https", "operations": ["GET"]},
            {"name": "shared-api", "host": "api.shared.test",
             "protocol": "https", "operations": ["GET"]},
            {"name": "any-api", "host": "api.any.test",
             "protocol": "https", "operations": ["*"]},
            {"name": "orders-pg", "host": "db.orders.test",
             "protocol": "postgres", "operations": ["*"]}
        ],
        "grants": [
            {"subject": "alice@acme.test", "workload": "claude-code",
             "resource": "billing-api", "operations": ["GET"], "environment": "development"},
            {"subject": "alice@acme.test", "workload": "claude-code",
             "resource": "shared-api", "operations": ["GET"], "environment": "development"},
            {"subject": "alice@acme.test", "workload": "claude-code",
             "resource": "shared-api", "operations": ["GET"], "environment": "production"},
            {"subject": "alice@acme.test", "workload": "claude-code",
             "resource": "any-api", "operations": ["*"], "environment": "development"},
            {"subject": "alice@acme.test", "workload": "claude-code",
             "resource": "orders-pg", "operations": ["*"], "environment": "development"},
            {"subject": "alice@acme.test", "workload": "claude-code",
             "resource": "ghost", "operations": ["GET"], "environment": "development"},
            {"subject": "alice@acme.test", "workload": "ci",
             "resource": "orders-pg", "operations": ["connect"], "environment": "development"},
            {"subject": "mallory@acme.test", "workload": "claude-code",
             "resource": "billing-api", "operations": [], "environment": "development"},
            {"subject": "mallory@acme.test", "workload": "claude-code",
             "resource": "shared-api", "operations": ["GET"], "environment": "staging"}
        ]}"#,
    )
    .unwrap()
}

pub(crate) fn resource(name: &str, operations: &[&str], project: Option<&str>) -> ResourcePolicy {
    ResourcePolicy {
        name: name.to_string(),
        host: "host.test".to_string(),
        protocol: "https".to_string(),
        operations: operations
            .iter()
            .map(|operation| (*operation).to_string())
            .collect(),
        materialization: Materialization::Retrieve,
        credential_ref: None,
        source: None,
        project: project.map(str::to_string),
        connection: Connection::default(),
    }
}

pub(crate) fn grant(
    subject: &str,
    workload: &str,
    resource: &str,
    operations: &[&str],
    environment: &str,
) -> GrantRule {
    GrantRule {
        subject: subject.to_string(),
        workload: workload.to_string(),
        resource: resource.to_string(),
        operations: operations
            .iter()
            .map(|operation| (*operation).to_string())
            .collect(),
        environment: environment.to_string(),
    }
}

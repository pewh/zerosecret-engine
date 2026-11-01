use serde::{Deserialize, Serialize};
use zs_identity::{Subject, WorkloadLabel};

mod cedar;
pub mod connection;
pub mod source;
pub use connection::*;
pub use source::*;

#[cfg(test)]
mod fixtures;
#[cfg(test)]
mod reference;

// `Default` is the empty policy that grants nothing; never fall back to it on denial.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Policy {
    pub resources: Vec<ResourcePolicy>,
    pub grants: Vec<GrantRule>,
    pub version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourcePolicy {
    pub name: String,
    pub host: String,
    pub protocol: String,
    pub operations: Vec<String>,
    #[serde(default)]
    pub materialization: Materialization,
    #[serde(default)]
    pub credential_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<CredentialSource>,
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default, skip_serializing_if = "Connection::is_default")]
    pub connection: Connection,
}

impl ResourcePolicy {
    pub fn resolved_source(&self) -> Result<CredentialSource, SourceError> {
        match (&self.source, &self.credential_ref) {
            (Some(_), Some(_)) => Err(SourceError::new("both source and credential_ref are set")),
            (Some(source), None) => Ok(source.clone()),
            (None, Some(reference)) => Ok(CredentialSource::File {
                reference: reference.clone(),
            }),
            (None, None) => Ok(CredentialSource::File {
                reference: format!("vault:kv/{}", self.name),
            }),
        }
    }

    pub fn checked_source(&self) -> Result<CredentialSource, SourceError> {
        let source = self.resolved_source()?;
        source.validate()?;
        if source
            .mode()
            .is_some_and(|mode| mode != self.materialization)
        {
            return Err(SourceError::new("source does not match materialization"));
        }
        Ok(source)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Materialization {
    #[default]
    Retrieve,
    Exchange,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrantRule {
    pub subject: String,
    pub workload: String,
    pub resource: String,
    pub operations: Vec<String>,
    pub environment: String,
}

pub const ANY_METHOD: &str = "*";
pub const CONNECT: &str = "connect";

// `*` names every HTTP method. It never names `connect`, so it cannot widen an L3 grant.
pub fn permits(operations: &[String], operation: &str) -> bool {
    operations
        .iter()
        .any(|o| o == operation || (o == ANY_METHOD && operation != CONNECT))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Operation {
    pub kind: String,
}

#[derive(Debug, thiserror::Error)]
#[error("policy denied: {reason}")]
pub struct PolicyDenied {
    pub reason: String,
}

#[derive(Debug)]
pub struct Evaluation {
    pub resource: ResourcePolicy,
    pub grant: GrantRule,
}

pub fn evaluate(
    policy: &Policy,
    subject: &Subject,
    workload: &WorkloadLabel,
    resource_name: &str,
    operation: &str,
) -> Result<Evaluation, PolicyDenied> {
    evaluate_matching(
        policy,
        subject,
        workload,
        resource_name,
        operation,
        None,
        None,
    )
}

// `environment` must come from trusted configuration, never from the requesting client.
pub fn evaluate_in(
    policy: &Policy,
    subject: &Subject,
    workload: &WorkloadLabel,
    resource_name: &str,
    operation: &str,
    environment: &str,
) -> Result<Evaluation, PolicyDenied> {
    evaluate_matching(
        policy,
        subject,
        workload,
        resource_name,
        operation,
        Some(environment),
        None,
    )
}

// `project` must come from the caller's enrolment row, never from the request.
pub fn evaluate_scoped(
    policy: &Policy,
    subject: &Subject,
    workload: &WorkloadLabel,
    resource_name: &str,
    operation: &str,
    environment: &str,
    project: Option<&str>,
) -> Result<Evaluation, PolicyDenied> {
    evaluate_matching(
        policy,
        subject,
        workload,
        resource_name,
        operation,
        Some(environment),
        Some(project),
    )
}

// Exactly one `None` must deny, or enrolling without a project would reach everything.
pub fn authorizes_project(resource: Option<&str>, caller: Option<&str>) -> bool {
    match (resource, caller) {
        (None, None) => true,
        (None, Some(_)) => true,
        (Some(_), None) => false,
        (Some(r), Some(c)) => r == c,
    }
}

fn evaluate_matching(
    policy: &Policy,
    subject: &Subject,
    workload: &WorkloadLabel,
    resource_name: &str,
    operation: &str,
    environment: Option<&str>,
    project: Option<Option<&str>>,
) -> Result<Evaluation, PolicyDenied> {
    let terms = cedar::Terms {
        subject: subject.as_str(),
        workload: workload.as_str(),
        resource: resource_name,
        operation,
        environment,
        project,
    };
    let outcome = cedar::decide(policy, &terms);

    if let Some(environment) = environment
        && outcome.fired.contains(&cedar::Fired::Environment)
    {
        return Err(PolicyDenied {
            reason: format!(
                "{} has no grant for {} on {} in environment {}",
                subject.as_str(),
                workload.as_str(),
                resource_name,
                environment
            ),
        });
    }
    if outcome.fired.contains(&cedar::Fired::NoGrant) {
        return Err(PolicyDenied {
            reason: format!(
                "{} has no grant for {} on {}",
                subject.as_str(),
                workload.as_str(),
                resource_name
            ),
        });
    }
    let resource = policy
        .resources
        .iter()
        .find(|resource| resource.name == resource_name)
        .ok_or_else(|| PolicyDenied {
            reason: format!("unknown resource {}", resource_name),
        })?;
    if outcome.fired.contains(&cedar::Fired::ResourceOperation) {
        return Err(PolicyDenied {
            reason: format!("operation {} not allowed on {}", operation, resource_name),
        });
    }
    if outcome.fired.contains(&cedar::Fired::Project) {
        return Err(PolicyDenied {
            reason: format!(
                "{} is in project {}, which is not the caller's project {}",
                resource_name,
                resource.project.as_deref().unwrap_or("<none>"),
                project.flatten().unwrap_or("<none>")
            ),
        });
    }
    if !outcome.allowed || outcome.errored {
        return Err(PolicyDenied {
            reason: format!("policy evaluation failed for {}", resource_name),
        });
    }
    let grant = policy
        .grants
        .iter()
        .find(|grant| {
            grant.subject == subject.as_str()
                && grant.workload == workload.as_str()
                && grant.resource == resource_name
                && permits(&grant.operations, operation)
                && environment.is_none_or(|environment| grant.environment == environment)
        })
        .ok_or_else(|| PolicyDenied {
            reason: format!("policy evaluation failed for {}", resource_name),
        })?;
    Ok(Evaluation {
        resource: resource.clone(),
        grant: grant.clone(),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    use crate::fixtures;

    #[test]
    fn allows_granted_operation() {
        let p = fixtures::policy();
        let subject = Subject::new("alice@company.com").unwrap();
        let workload = WorkloadLabel::new("claude-code").unwrap();
        assert!(evaluate(&p, &subject, &workload, "stripe-production", "GET").is_ok());
    }

    #[test]
    fn denies_ungranted_operation() {
        let p = fixtures::policy();
        let subject = Subject::new("alice@company.com").unwrap();
        let workload = WorkloadLabel::new("claude-code").unwrap();
        assert!(evaluate(&p, &subject, &workload, "stripe-production", "POST").is_err());
    }

    #[test]
    fn any_method_grant_allows_every_http_method() {
        let p = fixtures::any_method_policy();
        let subject = Subject::new("alice@company.com").unwrap();
        let workload = WorkloadLabel::new("claude-code").unwrap();
        for method in [
            "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "*",
        ] {
            assert!(
                evaluate(&p, &subject, &workload, "any-api", method).is_ok(),
                "{method}"
            );
        }
    }

    #[test]
    fn any_method_never_names_connect() {
        let p = fixtures::any_method_policy();
        let subject = Subject::new("alice@company.com").unwrap();
        let workload = WorkloadLabel::new("claude-code").unwrap();
        assert!(evaluate(&p, &subject, &workload, "orders-pg", CONNECT).is_err());
        assert!(!permits(&["*".into()], CONNECT));
    }

    #[test]
    fn a_request_for_any_method_does_not_widen_a_listed_grant() {
        let p = fixtures::policy();
        let subject = Subject::new("alice@company.com").unwrap();
        let workload = WorkloadLabel::new("claude-code").unwrap();
        assert!(evaluate(&p, &subject, &workload, "stripe-production", ANY_METHOD).is_err());
    }

    #[test]
    fn denies_unknown_resource() {
        let p = fixtures::policy();
        let subject = Subject::new("alice@company.com").unwrap();
        let workload = WorkloadLabel::new("claude-code").unwrap();
        let err = evaluate(&p, &subject, &workload, "openai-production", "GET").unwrap_err();
        assert!(err.reason.contains("no grant"));
    }

    #[test]
    fn denies_environment_mismatch() {
        let p = fixtures::policy();
        let subject = Subject::new("alice@company.com").unwrap();
        let workload = WorkloadLabel::new("claude-code").unwrap();
        let err = evaluate_in(
            &p,
            &subject,
            &workload,
            "stripe-production",
            "GET",
            "production",
        )
        .unwrap_err();
        assert!(
            err.reason.contains("environment"),
            "the denial must name the environment, got: {}",
            err.reason
        );
    }

    #[test]
    fn allows_matching_environment() {
        let p = fixtures::policy();
        let subject = Subject::new("alice@company.com").unwrap();
        let workload = WorkloadLabel::new("claude-code").unwrap();
        let evaluation = evaluate_in(
            &p,
            &subject,
            &workload,
            "stripe-production",
            "GET",
            "development",
        )
        .unwrap();
        assert_eq!(evaluation.grant.environment, "development");
    }

    #[test]
    fn project_authorization_matrix() {
        assert!(
            authorizes_project(None, None),
            "pre-project policy still works"
        );
        assert!(
            authorizes_project(None, Some("billing")),
            "an org-wide resource is reachable from within a project"
        );
        assert!(
            !authorizes_project(Some("billing"), None),
            "absent caller scope is not a wildcard"
        );
        assert!(authorizes_project(Some("billing"), Some("billing")));
        assert!(!authorizes_project(Some("billing"), Some("analytics")));
    }

    #[test]
    fn a_caller_reaches_its_own_projects_resource() {
        let p = fixtures::projected_policy();
        let subject = Subject::new("alice@acme.test").unwrap();
        let workload = WorkloadLabel::new("claude-code").unwrap();
        assert!(
            evaluate_scoped(
                &p,
                &subject,
                &workload,
                "billing-api",
                "GET",
                "development",
                Some("billing")
            )
            .is_ok()
        );
    }

    #[test]
    fn a_caller_is_denied_another_projects_resource() {
        let p = fixtures::projected_policy();
        let subject = Subject::new("alice@acme.test").unwrap();
        let workload = WorkloadLabel::new("claude-code").unwrap();
        let err = evaluate_scoped(
            &p,
            &subject,
            &workload,
            "billing-api",
            "GET",
            "development",
            Some("analytics"),
        )
        .unwrap_err();
        assert!(
            err.reason.contains("project"),
            "the denial must name the project, got: {}",
            err.reason
        );
    }

    #[test]
    fn an_unprojected_resource_is_reachable_from_any_project() {
        let p = fixtures::projected_policy();
        let subject = Subject::new("alice@acme.test").unwrap();
        let workload = WorkloadLabel::new("claude-code").unwrap();
        for caller in [None, Some("billing"), Some("analytics")] {
            assert!(
                evaluate_scoped(
                    &p,
                    &subject,
                    &workload,
                    "shared-api",
                    "GET",
                    "development",
                    caller
                )
                .is_ok(),
                "shared-api must be reachable from {caller:?}"
            );
        }
    }

    #[test]
    fn an_unprojected_caller_cannot_reach_a_projected_resource() {
        let p = fixtures::projected_policy();
        let subject = Subject::new("alice@acme.test").unwrap();
        let workload = WorkloadLabel::new("claude-code").unwrap();
        assert!(
            evaluate_scoped(
                &p,
                &subject,
                &workload,
                "billing-api",
                "GET",
                "development",
                None
            )
            .is_err(),
            "enrolling without a project must not reach everything"
        );
    }

    #[test]
    fn the_right_project_does_not_substitute_for_a_grant() {
        let p = fixtures::projected_policy();
        let subject = Subject::new("mallory@acme.test").unwrap();
        let workload = WorkloadLabel::new("claude-code").unwrap();
        let err = evaluate_scoped(
            &p,
            &subject,
            &workload,
            "billing-api",
            "GET",
            "development",
            Some("billing"),
        )
        .unwrap_err();
        assert!(
            err.reason.contains("no grant"),
            "a subject with no rule must be denied for the missing grant, got: {}",
            err.reason
        );
    }

    #[test]
    fn the_project_check_is_what_makes_the_difference() {
        let p = fixtures::projected_policy();
        let subject = Subject::new("alice@acme.test").unwrap();
        let workload = WorkloadLabel::new("claude-code").unwrap();
        assert!(
            evaluate_in(&p, &subject, &workload, "billing-api", "GET", "development").is_ok(),
            "every non-project term must match, or the comparison below proves nothing"
        );
        assert!(
            evaluate_scoped(
                &p,
                &subject,
                &workload,
                "billing-api",
                "GET",
                "development",
                Some("analytics")
            )
            .is_err(),
            "the project, and only the project, must turn this allow into a deny"
        );
    }

    #[test]
    fn a_grant_rules_environment_cannot_be_widened_by_the_caller() {
        let p = fixtures::policy();
        let subject = Subject::new("alice@company.com").unwrap();
        let workload = WorkloadLabel::new("claude-code").unwrap();
        for attempted in ["production", "staging", "", "development "] {
            assert!(
                evaluate_in(
                    &p,
                    &subject,
                    &workload,
                    "stripe-production",
                    "GET",
                    attempted
                )
                .is_err(),
                "environment {attempted:?} must not match the rule's `development`"
            );
        }
    }

    fn dispatch(
        policy: &Policy,
        subject: &Subject,
        workload: &WorkloadLabel,
        resource: &str,
        operation: &str,
        environment: Option<&str>,
        project: Option<Option<&str>>,
    ) -> Result<Evaluation, PolicyDenied> {
        match (environment, project) {
            (None, None) => evaluate(policy, subject, workload, resource, operation),
            (Some(environment), None) => {
                evaluate_in(policy, subject, workload, resource, operation, environment)
            }
            (Some(environment), Some(project)) => evaluate_scoped(
                policy,
                subject,
                workload,
                resource,
                operation,
                environment,
                project,
            ),
            (None, Some(_)) => unreachable!("a project check needs an environment"),
        }
    }

    // The file is the case source; the grid integration test pins the expected results.
    const GRID: &str = include_str!("../vectors/grid.json");

    #[test]
    fn cedar_and_the_reference_agree_on_every_input() {
        let file: serde_json::Value = serde_json::from_str(GRID).unwrap();
        let policy: Policy = serde_json::from_value(file["context"].clone()).unwrap();
        assert_eq!(
            policy,
            fixtures::grid_policy(),
            "the grid file's context is not the grid policy"
        );
        let cases = file["cases"].as_array().unwrap();
        for case in cases {
            let name = case["name"].as_str().unwrap();
            let input = &case["input"];
            let subject = Subject::new(input["subject"].as_str().unwrap()).unwrap();
            let workload = WorkloadLabel::new(input["workload"].as_str().unwrap()).unwrap();
            let resource = input["resource"].as_str().unwrap();
            let operation = input["operation"].as_str().unwrap();
            let environment = input.get("environment").and_then(serde_json::Value::as_str);
            let project = input.get("project").map(|value| value.as_str());
            let actual = dispatch(
                &policy,
                &subject,
                &workload,
                resource,
                operation,
                environment,
                project,
            );
            let expected = reference::evaluate_scoped(
                &policy,
                &subject,
                &workload,
                resource,
                operation,
                environment,
                project,
            );
            match (&actual, &expected) {
                (Ok(actual), Ok(expected)) => {
                    assert_eq!(actual.resource, expected.resource, "{name}");
                    assert_eq!(actual.grant, expected.grant, "{name}");
                }
                (Err(actual), Err(expected)) => {
                    assert_eq!(actual.reason, expected.reason, "{name}");
                }
                _ => panic!(
                    "Cedar and the reference disagree: {name}: actual={actual:?} expected={expected:?}"
                ),
            }
        }
    }

    #[test]
    fn the_any_method_rule_agrees_with_permits() {
        let subject = Subject::new("alice@company.com").unwrap();
        let workload = WorkloadLabel::new("claude-code").unwrap();
        for grant_operations in [&["*"][..], &["GET"], &["connect"], &[]] {
            let policy = Policy {
                version: 1,
                resources: vec![fixtures::resource("any-api", &["*", "connect"], None)],
                grants: vec![fixtures::grant(
                    "alice@company.com",
                    "claude-code",
                    "any-api",
                    grant_operations,
                    "development",
                )],
            };
            let grant_operations = grant_operations
                .iter()
                .map(|operation| (*operation).to_string())
                .collect::<Vec<_>>();
            for operation in ["GET", "POST", "*", "connect", "CONNECT", "PATCH"] {
                let expected = permits(&grant_operations, operation);
                assert_eq!(
                    evaluate(&policy, &subject, &workload, "any-api", operation).is_ok(),
                    expected,
                    "operations={grant_operations:?} operation={operation}"
                );
                assert_eq!(
                    evaluate_in(
                        &policy,
                        &subject,
                        &workload,
                        "any-api",
                        operation,
                        "development"
                    )
                    .is_ok(),
                    expected,
                    "operations={grant_operations:?} operation={operation} environment=development"
                );
            }
        }
    }

    #[test]
    fn the_project_forbid_agrees_with_authorizes_project() {
        let policy = fixtures::projected_policy();
        let subject = Subject::new("alice@acme.test").unwrap();
        let workload = WorkloadLabel::new("claude-code").unwrap();
        let cases = [
            (None, None),
            (None, Some("billing")),
            (Some("billing"), None),
            (Some("billing"), Some("billing")),
            (Some("billing"), Some("analytics")),
        ];
        for (resource_project, caller) in cases {
            let resource = if resource_project.is_some() {
                "billing-api"
            } else {
                "shared-api"
            };
            let expected = authorizes_project(resource_project, caller);
            let actual = evaluate_scoped(
                &policy,
                &subject,
                &workload,
                resource,
                "GET",
                "development",
                caller,
            );
            assert_eq!(
                actual.is_ok(),
                expected,
                "resource={resource} caller={caller:?}"
            );
        }
    }

    #[test]
    fn an_evaluation_error_never_allows() {
        let policy = Policy {
            version: 1,
            resources: vec![fixtures::resource("known", &["GET"], None)],
            grants: vec![fixtures::grant(
                "alice@company.com",
                "claude-code",
                "ghost",
                &["GET"],
                "development",
            )],
        };
        let subject = Subject::new("alice@company.com").unwrap();
        let workload = WorkloadLabel::new("claude-code").unwrap();
        let err = evaluate(&policy, &subject, &workload, "ghost", "GET").unwrap_err();
        assert_eq!(err.reason, "unknown resource ghost");
        let outcome = cedar::decide(
            &policy,
            &cedar::Terms {
                subject: "alice@company.com",
                workload: "claude-code",
                resource: "ghost",
                operation: "GET",
                environment: None,
                project: None,
            },
        );
        assert!(outcome.errored);
        assert!(!outcome.allowed);
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore)]
    fn a_large_policy_evaluates_quickly() {
        let resources = (0..10)
            .map(|index| fixtures::resource(&format!("resource-{index}"), &["GET"], None))
            .collect::<Vec<_>>();
        let grants = (0..100)
            .flat_map(|subject| {
                (0..10).map(move |resource| {
                    fixtures::grant(
                        &format!("alice{subject}@acme.test"),
                        "claude-code",
                        &format!("resource-{resource}"),
                        &["GET"],
                        "development",
                    )
                })
            })
            .collect::<Vec<_>>();
        let policy = Policy {
            version: 1,
            resources,
            grants,
        };
        let subject = Subject::new("alice50@acme.test").unwrap();
        let workload = WorkloadLabel::new("claude-code").unwrap();
        let mut timings = (0..100)
            .map(|_| {
                let start = std::time::Instant::now();
                assert!(
                    evaluate_scoped(
                        &policy,
                        &subject,
                        &workload,
                        "resource-5",
                        "GET",
                        "development",
                        Some("billing")
                    )
                    .is_ok()
                );
                start.elapsed()
            })
            .collect::<Vec<_>>();
        timings.sort();
        let median = timings[timings.len() / 2];
        println!("median {median:?}");
        assert!(
            median < std::time::Duration::from_millis(5),
            "median {median:?}"
        );
    }
}

use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::LazyLock;

use cedar_policy::{
    Authorizer, Context, Decision, Entities, Entity, EntityId, EntityTypeName, EntityUid,
    PolicySet, Request, RestrictedExpression, Schema,
};

use crate::Policy;

const POLICY_SET: &str = include_str!("zerosecret.cedar");
const SCHEMA_TEXT: &str = include_str!("zerosecret.cedarschema");

struct Engine {
    schema: Schema,
    policies: PolicySet,
    names: HashMap<String, String>,
}

static ENGINE: LazyLock<Option<Engine>> = LazyLock::new(|| {
    let policies = PolicySet::from_str(POLICY_SET).ok()?;
    let names = policies
        .policies()
        .filter_map(|policy| {
            policy
                .annotation("id")
                .map(|name| (policy.id().to_string(), name.to_string()))
        })
        .collect();
    Some(Engine {
        schema: Schema::from_str(SCHEMA_TEXT).ok()?,
        policies,
        names,
    })
});

pub(crate) struct Terms<'a> {
    pub subject: &'a str,
    pub workload: &'a str,
    pub resource: &'a str,
    pub operation: &'a str,
    pub environment: Option<&'a str>,
    pub project: Option<Option<&'a str>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fired {
    Environment,
    NoGrant,
    ResourceOperation,
    Project,
}

#[derive(Debug)]
pub(crate) struct Outcome {
    pub allowed: bool,
    pub fired: Vec<Fired>,
    pub errored: bool,
}

pub(crate) fn decide(policy: &Policy, terms: &Terms<'_>) -> Outcome {
    match decide_inner(policy, terms) {
        Ok(outcome) => outcome,
        Err(()) => Outcome {
            allowed: false,
            fired: Vec::new(),
            errored: true,
        },
    }
}

fn decide_inner(policy: &Policy, terms: &Terms<'_>) -> Result<Outcome, ()> {
    let engine = ENGINE.as_ref().ok_or(())?;
    let principal_uid = uid("ZeroSecret::User", terms.subject)?;
    let resource_uid = uid("ZeroSecret::Resource", terms.resource)?;
    let action_uid = uid("ZeroSecret::Action", "use")?;

    let mut grants = Vec::new();
    let mut scopes = Vec::new();
    for rule in policy
        .grants
        .iter()
        .filter(|rule| rule.subject == terms.subject)
    {
        for operation in &rule.operations {
            scopes.push(record([
                ("resource", rule.resource.as_str()),
                ("workload", rule.workload.as_str()),
                ("operation", operation.as_str()),
            ])?);
            grants.push(record([
                ("resource", rule.resource.as_str()),
                ("workload", rule.workload.as_str()),
                ("operation", operation.as_str()),
                ("environment", rule.environment.as_str()),
            ])?);
        }
    }

    let principal = Entity::new(
        principal_uid.clone(),
        HashMap::from([
            ("grants".to_string(), RestrictedExpression::new_set(grants)),
            ("scopes".to_string(), RestrictedExpression::new_set(scopes)),
        ]),
        HashSet::new(),
    )
    .map_err(|_| ())?;

    let mut entities = vec![principal];
    if let Some(resource) = policy
        .resources
        .iter()
        .find(|resource| resource.name == terms.resource)
    {
        let operations = resource
            .operations
            .iter()
            .cloned()
            .map(RestrictedExpression::new_string)
            .collect::<Vec<_>>();
        let mut attributes = HashMap::from([(
            "operations".to_string(),
            RestrictedExpression::new_set(operations),
        )]);
        if let Some(project) = &resource.project {
            attributes.insert(
                "project".to_string(),
                RestrictedExpression::new_string(project.clone()),
            );
        }
        entities
            .push(Entity::new(resource_uid.clone(), attributes, HashSet::new()).map_err(|_| ())?);
    }

    let mut pairs = vec![
        (
            "resource_name".to_string(),
            RestrictedExpression::new_string(terms.resource.to_string()),
        ),
        (
            "workload".to_string(),
            RestrictedExpression::new_string(terms.workload.to_string()),
        ),
        (
            "operation".to_string(),
            RestrictedExpression::new_string(terms.operation.to_string()),
        ),
        (
            "scoped".to_string(),
            RestrictedExpression::new_bool(terms.project.is_some()),
        ),
    ];
    if let Some(environment) = terms.environment {
        pairs.push((
            "environment".to_string(),
            RestrictedExpression::new_string(environment.to_string()),
        ));
    }
    if let Some(Some(project)) = terms.project {
        pairs.push((
            "project".to_string(),
            RestrictedExpression::new_string(project.to_string()),
        ));
    }
    let context = Context::from_pairs(pairs).map_err(|_| ())?;
    let request = Request::new(
        principal_uid,
        action_uid,
        resource_uid,
        context,
        Some(&engine.schema),
    )
    .map_err(|_| ())?;
    let entities = Entities::from_entities(entities, None).map_err(|_| ())?;

    let response = Authorizer::new().is_authorized(&request, &engine.policies, &entities);
    let errored = response.diagnostics().errors().next().is_some();
    let reasons: HashSet<String> = response
        .diagnostics()
        .reason()
        .filter_map(|id| engine.names.get(&id.to_string()).cloned())
        .collect();
    let fired = [
        ("environment", Fired::Environment),
        ("no-grant", Fired::NoGrant),
        ("resource-operation", Fired::ResourceOperation),
        ("project", Fired::Project),
    ]
    .into_iter()
    .filter(|(id, _)| reasons.contains(*id))
    .map(|(_, fired)| fired)
    .collect();

    Ok(Outcome {
        allowed: response.decision() == Decision::Allow && !errored,
        fired,
        errored,
    })
}

fn uid(entity_type: &str, id: &str) -> Result<EntityUid, ()> {
    let entity_type = EntityTypeName::from_str(entity_type).map_err(|_| ())?;
    Ok(EntityUid::from_type_name_and_id(
        entity_type,
        EntityId::new(id),
    ))
}

fn record<const N: usize>(fields: [(&str, &str); N]) -> Result<RestrictedExpression, ()> {
    RestrictedExpression::new_record(fields.into_iter().map(|(key, value)| {
        (
            key.to_string(),
            RestrictedExpression::new_string(value.to_string()),
        )
    }))
    .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::{Policy, fixtures};

    fn strict_validation() -> cedar_policy::ValidationResult {
        let schema = Schema::from_str(SCHEMA_TEXT).unwrap();
        let policies = PolicySet::from_str(POLICY_SET).unwrap();
        cedar_policy::Validator::new(schema)
            .validate(&policies, cedar_policy::ValidationMode::Strict)
    }

    #[test]
    fn the_policy_set_validates_strictly_against_the_schema() {
        let result = strict_validation();
        let errors = result
            .validation_errors()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        assert!(errors.is_empty(), "{errors:#?}");
        let engine = ENGINE.as_ref().unwrap();
        assert_eq!(engine.names.len(), engine.policies.policies().count());
    }

    fn terms<'a>(
        resource: &'a str,
        operation: &'a str,
        environment: Option<&'a str>,
        project: Option<Option<&'a str>>,
    ) -> Terms<'a> {
        Terms {
            subject: "alice@company.com",
            workload: "claude-code",
            resource,
            operation,
            environment,
            project,
        }
    }

    #[test]
    fn each_forbid_fires_alone() {
        let policy = fixtures::policy();
        let environment = decide(
            &policy,
            &terms("stripe-production", "GET", Some("production"), None),
        );
        assert!(!environment.allowed);
        assert_eq!(
            environment.fired,
            vec![Fired::Environment],
            "{environment:?}"
        );

        let no_grant = decide(
            &fixtures::policy(),
            &terms("openai-production", "GET", None, None),
        );
        assert!(!no_grant.allowed);
        assert_eq!(no_grant.fired, vec![Fired::NoGrant], "{no_grant:?}");

        let limited = Policy {
            version: 1,
            resources: vec![fixtures::resource("limited", &["GET"], None)],
            grants: vec![fixtures::grant(
                "alice@company.com",
                "claude-code",
                "limited",
                &["DELETE"],
                "development",
            )],
        };
        let resource_operation = decide(&limited, &terms("limited", "DELETE", None, None));
        assert!(!resource_operation.allowed);
        assert_eq!(
            resource_operation.fired,
            vec![Fired::ResourceOperation],
            "{resource_operation:?}"
        );

        let project = decide(
            &fixtures::projected_policy(),
            &Terms {
                subject: "alice@acme.test",
                workload: "claude-code",
                resource: "billing-api",
                operation: "GET",
                environment: Some("development"),
                project: Some(Some("analytics")),
            },
        );
        assert!(!project.allowed);
        assert_eq!(project.fired, vec![Fired::Project], "{project:?}");
    }

    #[test]
    fn a_granted_request_fires_nothing() {
        let outcome = decide(
            &fixtures::policy(),
            &terms("stripe-production", "GET", Some("development"), None),
        );
        assert!(outcome.allowed);
        assert!(outcome.fired.is_empty());
        assert!(!outcome.errored);
    }

    #[test]
    fn names_with_cedar_syntax_are_data() {
        let subject = "a\"b@x.test";
        let workload = "w\\n";
        let name = "r::\"s\"";
        let policy = Policy {
            version: 1,
            resources: vec![fixtures::resource(name, &["GET"], None)],
            grants: vec![fixtures::grant(
                subject,
                workload,
                name,
                &["GET"],
                "development",
            )],
        };
        let matching = decide(
            &policy,
            &Terms {
                subject,
                workload,
                resource: name,
                operation: "GET",
                environment: None,
                project: None,
            },
        );
        assert!(matching.allowed, "{matching:?}");

        let unnamed = decide(
            &policy,
            &Terms {
                subject,
                workload,
                resource: "r::\"t\"",
                operation: "GET",
                environment: None,
                project: None,
            },
        );
        assert!(!unnamed.allowed);
        assert_eq!(unnamed.fired, vec![Fired::NoGrant], "{unnamed:?}");
    }

    #[test]
    fn an_unknown_resource_errors_and_is_not_allowed() {
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
        let outcome = decide(&policy, &terms("ghost", "GET", None, None));
        assert!(!outcome.allowed);
        assert!(outcome.errored);
        assert!(!outcome.fired.contains(&Fired::NoGrant), "{outcome:?}");
    }
}

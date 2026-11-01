#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use serde_json::{Value, json};
use zs_identity::{Subject, WorkloadLabel};
use zs_policy::{
    AwsRegion, AwsSsmSource, Policy, RoleArn, SsmParameter, aws_ssm_session_policy, evaluate,
    evaluate_in, evaluate_scoped,
};
use zs_vectors::{Runner, check};

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("the input has no string {key:?}"))
}

fn decide(policy: &Policy, input: &Value) -> Value {
    let subject = Subject::new(text(input, "subject")).unwrap();
    let workload = WorkloadLabel::new(text(input, "workload")).unwrap();
    let resource = text(input, "resource");
    let operation = text(input, "operation");
    let environment = input
        .get("environment")
        .map(|value| value.as_str().unwrap());
    let project = input.get("project").map(|value| value.as_str());
    let result = match (environment, project) {
        (None, None) => evaluate(policy, &subject, &workload, resource, operation),
        (Some(environment), None) => evaluate_in(
            policy,
            &subject,
            &workload,
            resource,
            operation,
            environment,
        ),
        (Some(environment), Some(project)) => evaluate_scoped(
            policy,
            &subject,
            &workload,
            resource,
            operation,
            environment,
            project,
        ),
        (None, Some(_)) => panic!("a project check needs an environment"),
    };
    match result {
        Ok(evaluation) => {
            let index = policy
                .grants
                .iter()
                .position(|grant| *grant == evaluation.grant)
                .unwrap();
            json!({"ok": {"grant_index": index}})
        }
        Err(denied) => json!({"err": denied.reason}),
    }
}

fn grid(context: &Value, input: &Value) -> Value {
    let policy: Policy = serde_json::from_value(context.clone()).unwrap();
    decide(&policy, input)
}

fn decisions_extra(_context: &Value, input: &Value) -> Value {
    let policy: Policy = serde_json::from_value(input["policy"].clone()).unwrap();
    decide(&policy, input)
}

fn session_policy(_context: &Value, input: &Value) -> Value {
    let source = AwsSsmSource {
        role_arn: RoleArn::parse(text(input, "role_arn")).unwrap(),
        region: AwsRegion::parse(text(input, "region")).unwrap(),
        parameter: SsmParameter::parse(text(input, "parameter")).unwrap(),
    };
    let policy = aws_ssm_session_policy(&source);
    json!({"policy": policy, "length": policy.len()})
}

fn policy_json(_context: &Value, input: &Value) -> Value {
    let document = input
        .as_str()
        .unwrap_or_else(|| panic!("the input is not a policy document text"));
    match accept(document) {
        Ok(policy) => json!({
            "accepted": true,
            "reserialized": serde_json::to_string(&policy).unwrap(),
        }),
        Err(error) => json!({"accepted": false, "error": error}),
    }
}

// The rule `control` applies when it seeds or serves a policy: parse, then check every
// resource's connection and its resolved credential source.
fn accept(document: &str) -> Result<Policy, String> {
    let policy: Policy = serde_json::from_str(document).map_err(parse_message)?;
    for resource in &policy.resources {
        resource
            .connection
            .validate(&resource.host, &resource.protocol)
            .map_err(|message| format!("resource {}: {message}", resource.name))?;
        resource
            .checked_source()
            .map_err(|error| format!("resource {}: {error}", resource.name))?;
    }
    Ok(policy)
}

// serde_json appends a line and a column; a contract must not pin either.
fn parse_message(error: serde_json::Error) -> String {
    let text = error.to_string();
    text.split(" at line ").next().unwrap_or(&text).to_string()
}

#[test]
fn every_vector_case_matches() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors");
    let runners = [
        Runner {
            file: "policy-json.json",
            case: policy_json,
        },
        Runner {
            file: "session-policy.json",
            case: session_policy,
        },
        Runner {
            file: "grid.json",
            case: grid,
        },
        Runner {
            file: "decisions-extra.json",
            case: decisions_extra,
        },
    ];
    check(&dir, &runners);
}

use zs_identity::{Subject, WorkloadLabel};

use crate::{Evaluation, Policy, PolicyDenied, authorizes_project, permits};

pub(crate) fn evaluate_scoped(
    policy: &Policy,
    subject: &Subject,
    workload: &WorkloadLabel,
    resource_name: &str,
    operation: &str,
    environment: Option<&str>,
    project: Option<Option<&str>>,
) -> Result<Evaluation, PolicyDenied> {
    let evaluation = evaluate_matching(
        policy,
        subject,
        workload,
        resource_name,
        operation,
        environment,
    )?;
    if let Some(project) = project
        && !authorizes_project(evaluation.resource.project.as_deref(), project)
    {
        return Err(PolicyDenied {
            reason: format!(
                "{} is in project {}, which is not the caller's project {}",
                resource_name,
                evaluation.resource.project.as_deref().unwrap_or("<none>"),
                project.unwrap_or("<none>")
            ),
        });
    }
    Ok(evaluation)
}

fn evaluate_matching(
    policy: &Policy,
    subject: &Subject,
    workload: &WorkloadLabel,
    resource_name: &str,
    operation: &str,
    environment: Option<&str>,
) -> Result<Evaluation, PolicyDenied> {
    if let Some(environment) = environment {
        let environment_exists = policy.grants.iter().any(|g| {
            g.subject == subject.as_str()
                && g.workload == workload.as_str()
                && g.resource == resource_name
                && permits(&g.operations, operation)
        });
        let environment_matches = policy.grants.iter().any(|g| {
            g.subject == subject.as_str()
                && g.workload == workload.as_str()
                && g.resource == resource_name
                && permits(&g.operations, operation)
                && g.environment == environment
        });
        if environment_exists && !environment_matches {
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
    }
    let grant = policy.grants.iter().find(|g| {
        g.subject == subject.as_str()
            && g.workload == workload.as_str()
            && g.resource == resource_name
            && permits(&g.operations, operation)
            && environment.is_none_or(|e| g.environment == e)
    });
    let grant = grant.ok_or_else(|| PolicyDenied {
        reason: format!(
            "{} has no grant for {} on {}",
            subject.as_str(),
            workload.as_str(),
            resource_name
        ),
    })?;
    let resource = policy
        .resources
        .iter()
        .find(|r| r.name == resource_name)
        .ok_or_else(|| PolicyDenied {
            reason: format!("unknown resource {}", resource_name),
        })?;
    if !permits(&resource.operations, operation) {
        return Err(PolicyDenied {
            reason: format!("operation {} not allowed on {}", operation, resource_name),
        });
    }
    Ok(Evaluation {
        resource: resource.clone(),
        grant: grant.clone(),
    })
}

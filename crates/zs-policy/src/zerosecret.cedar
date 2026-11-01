@id("grant")
permit (
  principal,
  action == ZeroSecret::Action::"use",
  resource
)
when {
  if context has environment then
    principal.grants.contains({resource: context.resource_name, workload: context.workload, operation: context.operation, environment: context.environment}) ||
    (context.operation != "connect" && principal.grants.contains({resource: context.resource_name, workload: context.workload, operation: "*", environment: context.environment}))
  else
    principal.scopes.contains({resource: context.resource_name, workload: context.workload, operation: context.operation}) ||
    (context.operation != "connect" && principal.scopes.contains({resource: context.resource_name, workload: context.workload, operation: "*"}))
};

@id("no-grant")
forbid (
  principal,
  action == ZeroSecret::Action::"use",
  resource
)
unless {
  principal.scopes.contains({resource: context.resource_name, workload: context.workload, operation: context.operation}) ||
  (context.operation != "connect" && principal.scopes.contains({resource: context.resource_name, workload: context.workload, operation: "*"}))
};

@id("environment")
forbid (
  principal,
  action == ZeroSecret::Action::"use",
  resource
)
when {
  context has environment &&
  (principal.scopes.contains({resource: context.resource_name, workload: context.workload, operation: context.operation}) ||
   (context.operation != "connect" && principal.scopes.contains({resource: context.resource_name, workload: context.workload, operation: "*"}))) &&
  !(principal.grants.contains({resource: context.resource_name, workload: context.workload, operation: context.operation, environment: context.environment}) ||
    (context.operation != "connect" && principal.grants.contains({resource: context.resource_name, workload: context.workload, operation: "*", environment: context.environment})))
};

@id("resource-operation")
forbid (
  principal,
  action == ZeroSecret::Action::"use",
  resource
)
unless {
  resource.operations.contains(context.operation) ||
  (context.operation != "connect" && resource.operations.contains("*"))
};

@id("project")
forbid (
  principal,
  action == ZeroSecret::Action::"use",
  resource
)
when {
  context.scoped &&
  resource has project &&
  !(context has project && context.project == resource.project)
};

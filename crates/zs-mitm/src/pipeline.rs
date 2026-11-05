use std::convert::Infallible;
use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use hyper::Response;
use tower::{Layer, Service, ServiceBuilder};

use zs_audit::{AuditError, Decision};
use zs_credential::Credential;
use zs_protocol::{Context as FlowContext, Destination, InjectedRequest, Protocol};

use crate::echo::{self, EchoNeedles, RequestSnapshot};
use crate::http1::{self, Body, Sender};
use crate::proxy::{FlowHandler, ProxyError, Upstream, connect_upstream, outbound};
use crate::scope::{PathScope, Refusal, ScopeDecision, target_refusal};

pub(crate) type Reply = Box<Response<Body>>;
pub(crate) type Injected = Option<(Arc<dyn Protocol>, Credential)>;

#[derive(Debug)]
pub(crate) struct RequestFacts {
    pub resource: String,
    pub operation: String,
    pub method: String,
    pub path: String,
    pub destination: Destination,
    pub subject: String,
    pub workload: String,
}

pub(crate) trait Report: Send + Sync {
    fn audit(
        &self,
        facts: &RequestFacts,
        decision: Decision,
        reason: Option<&str>,
    ) -> Result<u64, AuditError>;
    fn audit_failed(&self, error: AuditError);
    fn refused(&self, facts: &RequestFacts, rule: &'static str, seq: Option<u64>);
    fn forwarded(&self, facts: &RequestFacts, seq: u64);
    fn authorized(&self, facts: &RequestFacts, seq: u64);
    fn denied(&self, facts: &RequestFacts, stage: &'static str, seq: u64);
    fn relayed(&self, facts: &RequestFacts, status: u16, bytes: u64);
    fn failed(&self, facts: &RequestFacts, stage: &'static str, kind: &'static str);
}

pub(crate) enum Route {
    Tunnel {
        senders: Arc<tokio::sync::Mutex<Option<Sender>>>,
        upstream: Upstream,
    },
    Fresh {
        upstream: Upstream,
    },
}

pub(crate) struct Pending {
    pub facts: RequestFacts,
    pub request: InjectedRequest,
    pub extensions: hyper::http::Extensions,
    pub authority: String,
    pub route: Route,
    pub report: Arc<dyn Report>,
    pub skip_inject: bool,
    // What the response head must not carry, set when a credential was injected.
    pub echo: Option<Arc<EchoNeedles>>,
}

fn audit_or_reply(
    report: &dyn Report,
    facts: &RequestFacts,
    decision: Decision,
    reason: Option<&str>,
) -> Result<u64, Reply> {
    match report.audit(facts, decision, reason) {
        Ok(seq) => Ok(seq),
        Err(error) => {
            report.audit_failed(error);
            Err(Box::new(http1::reply(http1::Reply::AuditUnavailable)))
        }
    }
}

pub(crate) fn authorize_only(
    handler: &Arc<dyn FlowHandler>,
    report: &dyn Report,
    scope: &PathScope,
    facts: &RequestFacts,
) -> Result<bool, Reply> {
    if facts.resource.is_empty() {
        return Ok(false);
    }
    match scope.decide(&facts.path) {
        ScopeDecision::Refuse => {
            let rule = target_refusal(&facts.path).map_or("unknown", Refusal::code);
            match report.audit(facts, Decision::Deny, Some(rule)) {
                Ok(seq) => {
                    report.refused(facts, rule, Some(seq));
                    Err(Box::new(http1::reply(http1::Reply::Refused)))
                }
                Err(error) => {
                    report.audit_failed(error);
                    Err(Box::new(http1::reply(http1::Reply::AuditUnavailable)))
                }
            }
        }
        ScopeDecision::Forward => {
            let seq = audit_or_reply(report, facts, Decision::Passthrough, None)?;
            report.forwarded(facts, seq);
            Ok(true)
        }
        ScopeDecision::Inject => match identity_and_authorize(handler, facts) {
            Ok(()) => Ok(false),
            Err((stage, reason)) => {
                let seq = audit_or_reply(report, facts, Decision::Deny, Some(&reason))?;
                report.denied(facts, stage, seq);
                Err(Box::new(http1::reply(http1::Reply::Denied)))
            }
        },
    }
}

fn identity_and_authorize(
    handler: &Arc<dyn FlowHandler>,
    facts: &RequestFacts,
) -> Result<(), (&'static str, String)> {
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let subject = zs_identity::Subject::new(facts.subject.as_str())
            .map_err(|error| ("identity", error.to_string()))?;
        let workload = zs_identity::WorkloadLabel::new(facts.workload.as_str())
            .map_err(|error| ("identity", error.to_string()))?;
        let protocol = handler
            .protocol_for(&facts.resource)
            .ok_or_else(|| ("identity", format!("no protocol for {}", facts.resource)))?;
        protocol
            .authorize(&FlowContext {
                subject: &subject,
                workload: &workload,
            })
            .map_err(|denied| ("authorize", denied.audit_reason().to_string()))
    }));
    match outcome {
        Ok(result) => result,
        Err(_) => Err(("panic", "panic".to_string())),
    }
}

pub(crate) fn inject_only(
    handler: &Arc<dyn FlowHandler>,
    report: &dyn Report,
    facts: &RequestFacts,
    request: &mut InjectedRequest,
    authority: &str,
) -> Result<Injected, Reply> {
    if facts.resource.is_empty() {
        return Ok(None);
    }
    // A TRACE answer reflects the request, so it would carry the injected credential back.
    if request.method.eq_ignore_ascii_case("TRACE") {
        let seq = audit_or_reply(report, facts, Decision::Deny, Some("trace refused"))?;
        report.denied(facts, "method", seq);
        return Err(Box::new(http1::reply(http1::Reply::Denied)));
    }
    let stage = std::cell::Cell::new("identity");
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let protocol = handler.protocol_for(&facts.resource).ok_or_else(|| {
            zs_protocol::Denied::new(format!("no protocol for {}", facts.resource))
        })?;
        stage.set("materialize");
        let credential = handler.materialize(&facts.resource, &facts.operation)?;
        stage.set("inject");
        request.set_header("Host", authority);
        // A coded response body cannot be scanned for an echoed credential.
        request.set_header("Accept-Encoding", "identity");
        protocol.inject(request, &credential)?;
        Ok::<_, zs_protocol::Denied>((protocol, credential))
    }));
    let kind = match &outcome {
        Ok(Ok(_)) => None,
        Ok(Err(_)) => Some(stage.get()),
        Err(_) => Some("panic"),
    };
    match kind {
        None => {
            let seq = audit_or_reply(report, facts, Decision::Allow, None)?;
            report.authorized(facts, seq);
            match outcome {
                Ok(Ok(pair)) => Ok(Some(pair)),
                _ => Ok(None),
            }
        }
        Some(stage) => {
            let reason = match &outcome {
                Ok(Err(denied)) => denied.audit_reason(),
                _ => "panic",
            };
            let seq = audit_or_reply(report, facts, Decision::Deny, Some(reason))?;
            report.denied(facts, stage, seq);
            Err(Box::new(http1::reply(http1::Reply::Denied)))
        }
    }
}

type BoxFuture = Pin<Box<dyn Future<Output = Result<Response<Body>, Infallible>> + Send>>;

pub(crate) struct Authorize<S> {
    handler: Arc<dyn FlowHandler>,
    scope: PathScope,
    report: Arc<dyn Report>,
    inner: S,
}

impl<S> Service<Pending> for Authorize<S>
where
    S: Service<Pending, Response = Response<Body>, Error = Infallible>,
    S::Future: Send + 'static,
{
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = BoxFuture;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut pending: Pending) -> Self::Future {
        match authorize_only(&self.handler, &*self.report, &self.scope, &pending.facts) {
            Ok(skip) => pending.skip_inject = skip,
            Err(reply) => return Box::pin(async move { Ok(*reply) }),
        }
        Box::pin(self.inner.call(pending))
    }
}

pub(crate) struct Inject<S> {
    handler: Arc<dyn FlowHandler>,
    report: Arc<dyn Report>,
    inner: S,
}

impl<S> Service<Pending> for Inject<S>
where
    S: Service<Pending, Response = Response<Body>, Error = Infallible>,
    S::Future: Send + 'static,
{
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = BoxFuture;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut pending: Pending) -> Self::Future {
        if !pending.skip_inject {
            let before = RequestSnapshot::of(&pending.request);
            match inject_only(
                &self.handler,
                &*self.report,
                &pending.facts,
                &mut pending.request,
                &pending.authority,
            ) {
                Ok(Some((_, credential))) => {
                    pending.echo = Some(Arc::new(EchoNeedles::from_injection(
                        &before,
                        &pending.request,
                        credential.expose(),
                    )));
                    drop(credential);
                }
                Ok(None) => {}
                Err(reply) => return Box::pin(async move { Ok(*reply) }),
            }
        }
        Box::pin(self.inner.call(pending))
    }
}

pub(crate) struct Forward;

impl Service<Pending> for Forward {
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = BoxFuture;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, pending: Pending) -> Self::Future {
        Box::pin(async move { Ok(send(pending).await) })
    }
}

async fn send(pending: Pending) -> Response<Body> {
    let (senders, upstream) = match &pending.route {
        Route::Tunnel { senders, upstream } => (Some(senders.clone()), upstream.clone()),
        Route::Fresh { upstream } => (None, upstream.clone()),
    };
    let mut attempt = 0;
    let (response, sender) = loop {
        let (mut sender, reused) = match open(&senders, &upstream).await {
            Ok(pair) => pair,
            Err(error) => {
                pending
                    .report
                    .failed(&pending.facts, "connect", error.code());
                return http1::reply(http1::Reply::UpstreamUnreachable);
            }
        };
        let request = match outbound(&pending.request, &pending.authority, &pending.extensions) {
            Ok(request) => request,
            Err(error) => {
                pending
                    .report
                    .failed(&pending.facts, "request", error.code());
                return http1::reply(http1::Reply::Refused);
            }
        };
        if sender.ready().await.is_err() {
            pending.report.failed(&pending.facts, "relay", "closed");
            if !retryable(reused, attempt, true, &pending.facts) {
                return http1::reply(http1::Reply::UpstreamUnreachable);
            }
            attempt += 1;
            continue;
        }
        match sender.try_send_request(request).await {
            Ok(response) => break (response, sender),
            Err(mut error) => {
                let unwritten = error.take_message().is_some();
                let kind = ProxyError::Http(error.into_error()).code();
                pending.report.failed(&pending.facts, "relay", kind);
                if !retryable(reused, attempt, unwritten, &pending.facts) {
                    return http1::reply(http1::Reply::UpstreamUnreachable);
                }
                attempt += 1;
            }
        }
    };
    let refusal = pending.echo.as_ref().and_then(|needles| {
        if needles.found_in_response_head(&response) {
            Some("response echo")
        } else if echo::encoded(response.headers()) {
            Some("response encoded")
        } else {
            None
        }
    });
    if let Some(reason) = refusal {
        // The response and its connection are dropped unread; nothing of it reaches the client.
        drop(response);
        drop(sender);
        return match audit_or_reply(
            &*pending.report,
            &pending.facts,
            Decision::Deny,
            Some(reason),
        ) {
            Ok(seq) => {
                pending.report.denied(&pending.facts, "response", seq);
                http1::reply(http1::Reply::Denied)
            }
            Err(reply) => *reply,
        };
    }
    if let Some(senders) = &senders {
        *senders.lock().await = Some(sender);
    }
    let status = response.status().as_u16();
    let report = pending.report;
    let facts = Arc::new(pending.facts);
    let mut response = response.map(http1::boxed);
    if let Some(needles) = pending.echo {
        let (report, facts) = (report.clone(), facts.clone());
        response = response.map(|body| {
            echo::guarded(body, needles, move || {
                match report.audit(&facts, Decision::Deny, Some("response echo")) {
                    Ok(seq) => report.denied(&facts, "response", seq),
                    Err(error) => report.audit_failed(error),
                }
            })
        });
    }
    http1::counted(response, move |bytes| {
        report.relayed(&facts, status, bytes);
    })
}

fn retryable(reused: bool, attempt: u32, unwritten: bool, facts: &RequestFacts) -> bool {
    reused
        && attempt == 0
        && (unwritten
            || matches!(
                facts.method.as_str(),
                "GET" | "HEAD" | "OPTIONS" | "TRACE" | "PUT" | "DELETE"
            ))
}

async fn open(
    senders: &Option<Arc<tokio::sync::Mutex<Option<Sender>>>>,
    upstream: &Upstream,
) -> Result<(Sender, bool), ProxyError> {
    if let Some(senders) = senders {
        let mut slot = senders.lock().await;
        if let Some(sender) = slot.take()
            && !sender.is_closed()
        {
            return Ok((sender, true));
        }
    }
    connect_upstream(&upstream.host, upstream.port, upstream.tls, false)
        .await
        .map(|sender| (sender, false))
}

pub(crate) struct AuthorizeLayer {
    handler: Arc<dyn FlowHandler>,
    scope: PathScope,
    report: Arc<dyn Report>,
}

impl AuthorizeLayer {
    pub(crate) fn new(
        handler: Arc<dyn FlowHandler>,
        scope: PathScope,
        report: Arc<dyn Report>,
    ) -> Self {
        Self {
            handler,
            scope,
            report,
        }
    }
}

impl<S> Layer<S> for AuthorizeLayer {
    type Service = Authorize<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Authorize {
            handler: self.handler.clone(),
            scope: self.scope.clone(),
            report: self.report.clone(),
            inner,
        }
    }
}

pub(crate) struct InjectLayer {
    handler: Arc<dyn FlowHandler>,
    report: Arc<dyn Report>,
}

impl InjectLayer {
    pub(crate) fn new(handler: Arc<dyn FlowHandler>, report: Arc<dyn Report>) -> Self {
        Self { handler, report }
    }
}

impl<S> Layer<S> for InjectLayer {
    type Service = Inject<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Inject {
            handler: self.handler.clone(),
            report: self.report.clone(),
            inner,
        }
    }
}

pub(crate) fn pipeline(
    handler: Arc<dyn FlowHandler>,
    scope: PathScope,
    report: Arc<dyn Report>,
) -> Authorize<Inject<Forward>> {
    ServiceBuilder::new()
        .layer(AuthorizeLayer::new(handler.clone(), scope, report.clone()))
        .layer(InjectLayer::new(handler, report))
        .service(Forward)
}

pub(crate) async fn run(
    handler: Arc<dyn FlowHandler>,
    scope: PathScope,
    report: Arc<dyn Report>,
    pending: Pending,
) -> Response<Body> {
    let mut service = pipeline(handler, scope, report);
    match std::future::poll_fn(|cx| service.poll_ready(cx)).await {
        Ok(()) => match service.call(pending).await {
            Ok(response) => response,
            Err(never) => match never {},
        },
        Err(never) => match never {},
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use zs_protocol::Denied;

    const CANARY: &str = "sk_test_pipeline_canary";

    struct Fake {
        materialized: Arc<AtomicUsize>,
        protocol: Option<Arc<dyn Protocol>>,
    }

    impl FlowHandler for Fake {
        fn classify(&self, _destination: &Destination) -> crate::proxy::Flow {
            crate::proxy::Flow::Deny {
                reason: "not in this test".into(),
            }
        }
        fn subject(&self) -> String {
            "alice".into()
        }
        fn workload(&self) -> String {
            "w".into()
        }
        fn protocol_for(&self, _resource: &str) -> Option<Arc<dyn Protocol>> {
            self.protocol.clone()
        }
        fn materialize(&self, _resource: &str, _operation: &str) -> Result<Credential, Denied> {
            self.materialized.fetch_add(1, Ordering::SeqCst);
            Ok(Credential::from_bytes(CANARY.as_bytes().to_vec()).unwrap())
        }
        fn authorize_message(&self, _resource: &str, _operation: &str) -> Result<(), Denied> {
            Ok(())
        }
    }

    struct Allow;

    impl Protocol for Allow {
        fn matches(&self, _destination: &Destination) -> bool {
            true
        }
        fn authorize(&self, _context: &FlowContext) -> Result<(), Denied> {
            Ok(())
        }
        fn inject(
            &self,
            request: &mut InjectedRequest,
            credential: &Credential,
        ) -> Result<(), Denied> {
            request.set_header(
                "Authorization",
                format!("Bearer {}", String::from_utf8_lossy(credential.expose())),
            );
            Ok(())
        }
    }

    struct Refuse;

    impl Protocol for Refuse {
        fn matches(&self, _destination: &Destination) -> bool {
            true
        }
        fn authorize(&self, _context: &FlowContext) -> Result<(), Denied> {
            Err(Denied::new("workload has no grant"))
        }
        fn inject(
            &self,
            _request: &mut InjectedRequest,
            _credential: &Credential,
        ) -> Result<(), Denied> {
            Ok(())
        }
    }

    struct Panic;

    impl Protocol for Panic {
        fn matches(&self, _destination: &Destination) -> bool {
            true
        }
        fn authorize(&self, _context: &FlowContext) -> Result<(), Denied> {
            Ok(())
        }
        fn inject(
            &self,
            _request: &mut InjectedRequest,
            _credential: &Credential,
        ) -> Result<(), Denied> {
            panic!("inject panicked")
        }
    }

    #[derive(Default)]
    struct Recorder {
        facts: std::sync::Mutex<Vec<String>>,
        sequenced: AtomicUsize,
    }

    impl Report for Recorder {
        fn audit(
            &self,
            _facts: &RequestFacts,
            _decision: Decision,
            _reason: Option<&str>,
        ) -> Result<u64, AuditError> {
            Ok(self.sequenced.fetch_add(1, Ordering::SeqCst) as u64)
        }
        fn audit_failed(&self, _error: AuditError) {}
        fn refused(&self, facts: &RequestFacts, _rule: &'static str, _seq: Option<u64>) {
            self.facts.lock().unwrap().push(format!("{facts:?}"));
        }
        fn forwarded(&self, facts: &RequestFacts, _seq: u64) {
            self.facts.lock().unwrap().push(format!("{facts:?}"));
        }
        fn authorized(&self, facts: &RequestFacts, _seq: u64) {
            self.facts.lock().unwrap().push(format!("{facts:?}"));
        }
        fn denied(&self, facts: &RequestFacts, _stage: &'static str, _seq: u64) {
            self.facts.lock().unwrap().push(format!("{facts:?}"));
        }
        fn relayed(&self, _facts: &RequestFacts, _status: u16, _bytes: u64) {}
        fn failed(&self, _facts: &RequestFacts, _stage: &'static str, _kind: &'static str) {}
    }

    fn facts() -> RequestFacts {
        RequestFacts {
            resource: "r".into(),
            operation: "GET".into(),
            method: "GET".into(),
            path: "/v1/customers".into(),
            destination: Destination::new("h", 443),
            subject: "alice".into(),
            workload: "w".into(),
        }
    }

    fn request() -> InjectedRequest {
        InjectedRequest {
            method: "GET".into(),
            path: "/v1/customers".into(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    fn handler(protocol: Option<Arc<dyn Protocol>>) -> (Arc<dyn FlowHandler>, Arc<AtomicUsize>) {
        let materialized = Arc::new(AtomicUsize::new(0));
        let handler = Arc::new(Fake {
            materialized: materialized.clone(),
            protocol,
        });
        (handler, materialized)
    }

    #[test]
    fn a_denied_request_never_materializes() {
        let (handler, materialized) = handler(Some(Arc::new(Refuse)));
        let report = Recorder::default();
        let scope = PathScope::from_entries(Some(&["/v1/customers".to_string()][..])).unwrap();
        let denied = authorize_only(&handler, &report, &scope, &facts());
        let reply = denied.expect_err("the authorize layer must answer");
        assert_eq!(reply.status(), hyper::StatusCode::BAD_GATEWAY);
        assert_eq!(
            String::from_utf8_lossy(
                reply
                    .extensions()
                    .get::<hyper::ext::ReasonPhrase>()
                    .map(|phrase| phrase.as_bytes())
                    .unwrap_or(b"")
            ),
            "ZeroSecret denied"
        );
        let mut request = request();
        if authorize_only(&handler, &report, &scope, &facts()).is_ok() {
            let _ = inject_only(&handler, &report, &facts(), &mut request, "h");
        }
        assert_eq!(materialized.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn authorize_never_sees_the_credential() {
        let (handler, materialized) = handler(Some(Arc::new(Allow)));
        let report = Recorder::default();
        let scope = PathScope::from_entries(Some(&["/v1/customers".to_string()][..])).unwrap();
        assert!(authorize_only(&handler, &report, &scope, &facts()).is_ok());
        let mut request = request();
        let injected = inject_only(&handler, &report, &facts(), &mut request, "h")
            .expect("the inject layer answers");
        assert!(injected.is_some());
        assert_eq!(materialized.load(Ordering::SeqCst), 1);
        assert_eq!(
            request.header("Authorization"),
            Some(format!("Bearer {CANARY}").as_str())
        );
        let recorded = report.facts.lock().unwrap().clone();
        assert!(!recorded.is_empty());
        for facts in recorded {
            assert!(!facts.contains(CANARY), "{facts}");
        }
    }

    #[tokio::test]
    async fn a_denied_request_never_reaches_forward() {
        let (handler, materialized) = handler(Some(Arc::new(Refuse)));
        let report = Recorder::default();
        let scope = PathScope::from_entries(Some(&["/v1/customers".to_string()][..])).unwrap();
        let pending = Pending {
            facts: facts(),
            request: request(),
            extensions: hyper::http::Extensions::new(),
            authority: "h".into(),
            route: Route::Fresh {
                upstream: crate::proxy::Upstream {
                    host: "127.0.0.1".into(),
                    port: 9,
                    tls: false,
                },
            },
            report: Arc::new(report),
            skip_inject: false,
            echo: None,
        };
        let reply = run(handler.clone(), scope, pending.report.clone(), pending).await;
        assert_eq!(reply.status(), hyper::StatusCode::BAD_GATEWAY);
        let phrase = reply
            .extensions()
            .get::<hyper::ext::ReasonPhrase>()
            .map(|phrase| phrase.as_bytes().to_vec())
            .unwrap_or_default();
        assert_eq!(
            String::from_utf8_lossy(&phrase),
            "ZeroSecret denied",
            "Forward must not answer a denied request"
        );
        assert_eq!(materialized.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_panicking_inject_answers_denied() {
        let (handler, _materialized) = handler(Some(Arc::new(Panic)));
        let report = Recorder::default();
        let scope = PathScope::from_entries(Some(&["/v1/customers".to_string()][..])).unwrap();
        assert!(authorize_only(&handler, &report, &scope, &facts()).is_ok());
        let mut request = request();
        let reply = match inject_only(&handler, &report, &facts(), &mut request, "h") {
            Err(reply) => reply,
            Ok(_) => panic!("the inject layer must answer"),
        };
        assert_eq!(reply.status(), hyper::StatusCode::BAD_GATEWAY);
        assert!(request.header("Authorization").is_none());
    }
}

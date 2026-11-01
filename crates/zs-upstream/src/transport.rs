#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportKind {
    TimedOut,
    Unreachable,
    Tls,
    Other,
}

impl std::fmt::Display for TransportKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::TimedOut => "timed out",
            Self::Unreachable => "unreachable",
            Self::Tls => "tls",
            Self::Other => "transport error",
        })
    }
}

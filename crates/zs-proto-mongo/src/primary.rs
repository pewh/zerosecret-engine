use std::sync::Arc;

use tokio::sync::watch;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Known {
    Unknown,
    At(String),
    Stale(String),
}

#[derive(Clone)]
pub struct PrimaryState {
    sender: Arc<watch::Sender<Known>>,
}

impl Default for PrimaryState {
    fn default() -> Self {
        Self::new()
    }
}

impl PrimaryState {
    pub fn new() -> Self {
        let (sender, _) = watch::channel(Known::Unknown);
        Self {
            sender: Arc::new(sender),
        }
    }

    pub fn known(&self) -> Option<String> {
        match &*self.sender.borrow() {
            Known::At(address) => Some(address.clone()),
            Known::Unknown | Known::Stale(_) => None,
        }
    }

    pub fn found(&self, address: &str) {
        self.sender.send_if_modified(|known| {
            if *known == Known::At(address.to_string()) {
                false
            } else {
                *known = Known::At(address.to_string());
                true
            }
        });
    }

    pub fn stepped_down(&self, address: &str) {
        self.sender.send_if_modified(|known| {
            if *known == Known::At(address.to_string()) {
                *known = Known::Stale(address.to_string());
                true
            } else {
                false
            }
        });
    }

    pub fn subscribe(&self) -> watch::Receiver<Known> {
        self.sender.subscribe()
    }
}

pub fn must_close(pinned: &str, known: &Known) -> Option<&'static str> {
    match known {
        Known::At(address) if address != pinned => Some("newer_primary"),
        Known::Stale(address) if address == pinned => Some("hello"),
        Known::Stale(address) if address != pinned => Some("newer_primary"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn a_found_primary_is_known_and_a_step_down_makes_it_stale() {
        let state = PrimaryState::new();
        assert_eq!(state.known(), None);
        state.found("a:1");
        assert_eq!(state.known(), Some("a:1".to_string()));
        state.stepped_down("b:1");
        assert_eq!(
            state.known(),
            Some("a:1".to_string()),
            "another address is ignored"
        );
        state.stepped_down("a:1");
        assert_eq!(state.known(), None);
        assert_eq!(*state.subscribe().borrow(), Known::Stale("a:1".to_string()));
    }

    #[test]
    fn must_close_closes_only_connections_pinned_elsewhere() {
        let at = Known::At("a:1".to_string());
        let stale = Known::Stale("a:1".to_string());
        assert_eq!(must_close("a:1", &at), None);
        assert_eq!(must_close("b:1", &at), Some("newer_primary"));
        assert_eq!(must_close("a:1", &stale), Some("hello"));
        assert_eq!(must_close("b:1", &stale), Some("newer_primary"));
        assert_eq!(must_close("a:1", &Known::Unknown), None);
    }

    #[tokio::test]
    async fn subscribers_see_each_change() {
        let state = PrimaryState::new();
        let mut rx = state.subscribe();
        let clone = state.clone();
        clone.found("a:1");
        rx.changed().await.unwrap();
        assert_eq!(*rx.borrow_and_update(), Known::At("a:1".to_string()));
        state.found("a:1");
        assert!(
            !rx.has_changed().unwrap(),
            "the same address is not a change"
        );
        state.found("b:1");
        assert!(rx.has_changed().unwrap());
    }
}

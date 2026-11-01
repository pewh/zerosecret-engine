#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[test]
fn credential_type_has_no_debug_or_display() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile_fail/*.rs");
}

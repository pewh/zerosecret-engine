fn main() {
    println!("cargo:rerun-if-env-changed=ZS_BUILD_TEST_ENDPOINTS");
    if std::env::var("ZS_BUILD_TEST_ENDPOINTS").as_deref() == Ok("1") {
        if std::env::var("PROFILE").as_deref() == Ok("release") {
            panic!("ZS_BUILD_TEST_ENDPOINTS=1 is refused in a release build");
        }
        println!("cargo:rustc-cfg=zs_test_endpoints");
    }
}

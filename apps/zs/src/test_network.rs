use zs_upstream::http::Network;

pub fn network_from_env() -> Network {
    let mut network = Network::default();
    if let Ok(value) = std::env::var("ZS_TEST_AWS_RESOLVE") {
        for entry in value.split(',') {
            let Some((host, address)) = entry.split_once('=') else {
                continue;
            };
            let Ok(address) = address.trim().parse() else {
                continue;
            };
            network.resolve.push((host.trim().to_string(), address));
        }
    }
    if let Ok(path) = std::env::var("ZS_TEST_AWS_EXTRA_ROOT")
        && let Ok(loaded) = zs_upstream::load_ca(std::path::Path::new(&path))
    {
        network.extra_roots.extend(loaded.roots);
    }
    network
}

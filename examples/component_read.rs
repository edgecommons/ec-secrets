//! A stand-in for a component reading the vault: opens a local vault through the EdgeCommons
//! library the same way `gg.credentials()` does and prints one secret's value — proving that what
//! `ec-secrets` seeded is decryptable by a real component.
//!
//! Usage: `component_read <vault> <keyfile> <name>`

use edgecommons::credentials::{
    CredentialService, CredentialsConfig, KeyProviderConfig, VaultConfig, open,
};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let [_, vault, keyfile, name] = args.as_slice() else {
        eprintln!("usage: component_read <vault> <keyfile> <name>");
        std::process::exit(2);
    };

    // The credentials config a component carries to open a file-provider vault.
    let cfg = CredentialsConfig {
        vault: VaultConfig {
            path: vault.clone(),
            key_provider: KeyProviderConfig {
                kind: Some("file".to_string()),
                key_path: Some(keyfile.clone()),
                ..KeyProviderConfig::default()
            },
            keep_versions: 2,
            cache_ttl_secs: 300,
        },
        ..CredentialsConfig::default()
    };

    // This is the exact library call `gg.credentials()` makes.
    let creds = open(&cfg).expect("open the vault as a component");
    match creds.get_string(name).expect("read secret") {
        Some(value) => println!("component decrypted {name} = {value}"),
        None => {
            eprintln!("component: secret {name} not found");
            std::process::exit(1);
        }
    }
}

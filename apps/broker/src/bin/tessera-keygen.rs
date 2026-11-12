//! `tessera-keygen` — broker signing-key helper for rotations.
//!
//! Usage:
//!   tessera-keygen                     generate a new key (prints the private key + address)
//!   tessera-keygen --address 0x<hex>   derive the address for an existing key (key is not
//!                                      echoed back)
//!   tessera-keygen --help
//!
//! Exit codes: 0 = ok, 2 = usage error.

use std::process::ExitCode;

use tessera_broker::signer::{DigestSigner, LocalSigner};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!(
            "usage: tessera-keygen\n       \
             tessera-keygen --address 0x<32-byte-hex>"
        );
        return ExitCode::SUCCESS;
    }

    match args.first().map(String::as_str) {
        None => {
            let signer = LocalSigner::random();
            let key_hex = signer.private_key_hex();
            println!("address:     {}", signer.address_hex());
            println!("private key: {key_hex}");
            println!();
            println!("Next steps for a rotation:");
            println!("  1. Move the *current* address into BROKER_SIGNING_KEY_HISTORY.");
            println!("  2. Set BROKER_SIGNING_KEY to the new private key and restart.");
            println!("  3. Check GET /v1/verify/domain lists both signers.");
            println!("See docs/rotation.md for the full runbook.");
            ExitCode::SUCCESS
        }
        Some("--address") => {
            let Some(key) = args.get(1) else {
                eprintln!("error: --address needs a 32-byte hex key");
                return ExitCode::from(2);
            };
            match LocalSigner::from_hex(key) {
                Ok(signer) => {
                    println!("{}", signer.address_hex());
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("error: {err}");
                    ExitCode::from(2)
                }
            }
        }
        Some(other) => {
            eprintln!("error: unknown argument {other}");
            ExitCode::from(2)
        }
    }
}

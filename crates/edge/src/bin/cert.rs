//! Makes a self-signed certificate, so getting TLS running locally doesn't mean a
//! detour through openssl incantations.
//!
//! These are self-signed: fine for local work and for anything that will trust them
//! explicitly, useless on the public internet. Point the config at a real cert there.

use std::fs;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        eprintln!("usage: cloudveil-cert <out-dir> <hostname> [hostname...]");
        eprintln!("  e.g. cloudveil-cert certs demo.local '*.demo.local' localhost 127.0.0.1");
        bail!("not enough arguments");
    }

    let dir = PathBuf::from(&args[0]);
    let names: Vec<String> = args[1..].to_vec();
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;

    let cert = rcgen::generate_simple_self_signed(names.clone())
        .context("generating a self-signed certificate")?;

    /* named after the first hostname, with the wildcard star swapped out so the
       filename is not a shell glob waiting to happen */
    let stem = names[0].replace('*', "wildcard").replace(['/', '\\'], "_");
    let cert_path = dir.join(format!("{stem}.crt"));
    let key_path = dir.join(format!("{stem}.key"));

    fs::write(&cert_path, cert.cert.pem())
        .with_context(|| format!("writing {}", cert_path.display()))?;
    fs::write(&key_path, cert.signing_key.serialize_pem())
        .with_context(|| format!("writing {}", key_path.display()))?;

    println!("wrote {}", cert_path.display());
    println!("wrote {}", key_path.display());
    println!("  valid for: {}", names.join(", "));
    println!();
    println!("in your zone:");
    println!("    tls:");
    println!("      cert: \"{}\"", cert_path.display().to_string().replace('\\', "/"));
    println!("      key: \"{}\"", key_path.display().to_string().replace('\\', "/"));

    Ok(())
}

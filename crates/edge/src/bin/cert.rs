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
        eprintln!("usage:");
        eprintln!("  cloudveil-cert <out-dir> <hostname> [hostname...]");
        eprintln!("      a self-signed certificate for the edge's https listener");
        eprintln!("  cloudveil-cert --mtls <out-dir> <control-plane-hostname>");
        eprintln!("      a private CA, a server certificate for the control plane, and a");
        eprintln!("      client certificate for the edges");
        bail!("not enough arguments");
    }

    if args[0] == "--mtls" {
        return mtls(PathBuf::from(&args[1]), args.get(2).cloned());
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

/// A private CA, plus the two certificates the edge/control-plane link needs.
///
/// mTLS here is not about secrecy - the token already authenticates the request. It
/// is about making sure the thing holding the token is a machine you deployed, so a
/// leaked token alone is not enough to impersonate an edge.
fn mtls(dir: PathBuf, host: Option<String>) -> Result<()> {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose,
    };

    let host = host.unwrap_or_else(|| "localhost".to_string());
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;

    let mut ca_params = CertificateParams::new(vec![])?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Cloudveil internal CA");
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca_key = KeyPair::generate()?;
    let ca_key_pem = ca_key.serialize_pem();
    let ca = ca_params.self_signed(&ca_key)?;
    let issuer = rcgen::Issuer::new(ca_params.clone(), ca_key);

    let mut server = CertificateParams::new(vec![host.clone()])?;
    server
        .distinguished_name
        .push(DnType::CommonName, host.clone());
    server.use_authority_key_identifier_extension = true;
    server.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_key = KeyPair::generate()?;
    let server_cert = server.signed_by(&server_key, &issuer)?;

    let mut client = CertificateParams::new(vec!["cloudveil-edge".to_string()])?;
    client
        .distinguished_name
        .push(DnType::CommonName, "cloudveil-edge");
    client.use_authority_key_identifier_extension = true;
    client.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_key = KeyPair::generate()?;
    let client_cert = client.signed_by(&client_key, &issuer)?;

    let write = |name: &str, contents: String| -> Result<PathBuf> {
        let path = dir.join(name);
        fs::write(&path, contents).with_context(|| format!("writing {}", path.display()))?;
        Ok(path)
    };

    let ca_path = write("ca.crt", ca.pem())?;
    write("ca.key", ca_key_pem)?;
    let server_crt = write("control-plane.crt", server_cert.pem())?;
    let server_k = write("control-plane.key", server_key.serialize_pem())?;
    let client_crt = write("edge-client.crt", client_cert.pem())?;
    let client_k = write("edge-client.key", client_key.serialize_pem())?;

    let p = |path: &PathBuf| path.display().to_string().replace('\\', "/");

    println!("wrote a CA and two certificates into {}", dir.display());
    println!("  the CA key signs certificates - keep it off the edges entirely");
    println!();
    println!("control plane:");
    println!("  CLOUDVEIL_API_TLS_CERT={}", p(&server_crt));
    println!("  CLOUDVEIL_API_TLS_KEY={}", p(&server_k));
    println!("  CLOUDVEIL_API_CLIENT_CA={}", p(&ca_path));
    println!();
    println!("each edge:");
    println!("  CLOUDVEIL_CLIENT_CERT={}", p(&client_crt));
    println!("  CLOUDVEIL_CLIENT_KEY={}", p(&client_k));
    println!("  CLOUDVEIL_CP_CA={}", p(&ca_path));
    println!("  (and control_plane: \"https://{host}:9000\" in its config)");

    Ok(())
}

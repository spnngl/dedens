//! Cloudflare's `odoh-rs` as the client crypto of `../odoh.py`: it seals a DNS query to a target's configurations
//! and opens the target's response, and does nothing else. Files in, files out:
//!
//! ```text
//! odoh-rs-interop seal CONFIGS QUERY PADDING MESSAGE SECRET
//! odoh-rs-interop open QUERY PADDING SECRET RESPONSE ANSWER
//! ```
//!
//! `seal` takes the first supported configuration of `CONFIGS` (the bytes of `/.well-known/odohconfigs`) and writes
//! the body of the POST to `MESSAGE`, and the response secret to `SECRET`. `open` reads the body of the response and
//! writes the DNS answer. `PADDING` is the number of padding bytes of the query.

use std::error::Error;
use std::{env, fs};

use odoh_rs::{
    ObliviousDoHConfigContents, ObliviousDoHConfigs, ObliviousDoHMessage,
    ObliviousDoHMessagePlaintext, OdohSecret, compose, decrypt_response, encrypt_query, parse,
};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["seal", configs, query, padding, message, secret] => {
            seal(configs, query, padding.parse()?, message, secret)
        }
        ["open", query, padding, secret, response, answer] => {
            open(query, padding.parse()?, secret, response, answer)
        }
        _ => Err("usage: odoh-rs-interop seal|open ...; see the header of main.rs".into()),
    }
}

fn seal(
    configs: &str,
    query: &str,
    padding: usize,
    message: &str,
    secret: &str,
) -> Result<(), Box<dyn Error>> {
    let configs: ObliviousDoHConfigs = parse(&mut fs::read(configs)?.as_slice())?;
    let config: ObliviousDoHConfigContents = configs
        .supported()
        .into_iter()
        .next()
        .ok_or("no supported configuration")?
        .into();
    let plaintext = ObliviousDoHMessagePlaintext::new(fs::read(query)?, padding);
    let (sealed, response_secret) = encrypt_query(&plaintext, &config, &mut rand::rng())?;
    fs::write(message, compose(&sealed)?)?;
    fs::write(secret, response_secret)?;
    Ok(())
}

fn open(
    query: &str,
    padding: usize,
    secret: &str,
    response: &str,
    answer: &str,
) -> Result<(), Box<dyn Error>> {
    let plaintext = ObliviousDoHMessagePlaintext::new(fs::read(query)?, padding);
    let secret: OdohSecret = fs::read(secret)?
        .try_into()
        .map_err(|_| "the secret is not 16 bytes")?;
    let sealed: ObliviousDoHMessage = parse(&mut fs::read(response)?.as_slice())?;
    let opened = decrypt_response(&plaintext, &sealed, secret)?;
    fs::write(answer, opened.into_msg())?;
    Ok(())
}

//! Oblivious `DoH` (D78): the encryption of a query and a response on the captured response `a` (ID 0), with the
//! padding RFC 8467 recommends, for the suite of RFC 9230 §9. One call each; the ephemeral key and the
//! response nonce are fixed bytes, since a CSPRNG's cost is the platform's.

use core::convert::Infallible;
use std::hint::black_box;

use dedens_bench::wire;
use dedens_odoh::rand_core::{TryCryptoRng, TryRng};
use dedens_odoh::{
    ObliviousDoHConfigs, ObliviousDoHMessage, TargetKey, decrypt_query, decrypt_response,
    encrypt_query, encrypt_response, query_padding, response_padding,
};
use dedens_proto::{Edns, Message};
use divan::Bencher;

#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

fn main() {
    divan::main();
}

struct Fixed;

impl TryRng for Fixed {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(0x0707_0707)
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(0x0707_0707_0707_0707)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        dst.fill(7);
        Ok(())
    }
}

impl TryCryptoRng for Fixed {}

/// The query for the captured response `a`, ID 0 with EDNS, as a client sends it.
fn query() -> Vec<u8> {
    let response = wire("a");
    let message = Message::decode(&response).expect("decodes").message;
    let mut query = Message::query(0, message.questions[0].clone().into_owned());
    query.edns = Some(Edns::default());
    query.to_vec().expect("a query fits")
}

fn key() -> TargetKey {
    TargetKey::derive(&[7; 32])
}

/// The target's key as a client reads it, from the config the target publishes.
fn client_key(key: &TargetKey) -> dedens_odoh::ObliviousDoHConfigContents {
    let wire = ObliviousDoHConfigs::new(vec![key.config().clone()])
        .encode()
        .expect("one config");
    ObliviousDoHConfigs::parse(&wire).expect("parses").configs()[0].clone()
}

/// A query encrypted, with the context a response needs.
fn sealed_query(key: &TargetKey, query: &[u8]) -> (ObliviousDoHMessage, dedens_odoh::QueryContext) {
    encrypt_query(
        &client_key(key),
        query,
        query_padding(query.len()),
        &mut Fixed,
    )
    .expect("encrypts")
}

#[divan::bench]
fn target_key_derive() -> TargetKey {
    TargetKey::derive(black_box(&[7; 32]))
}

#[divan::bench]
fn encrypt_query_message(bencher: Bencher<'_, '_>) {
    let (key, query) = (key(), query());
    let config = client_key(&key);
    bencher.bench_local(|| {
        encrypt_query(
            &config,
            black_box(&query),
            query_padding(query.len()),
            &mut Fixed,
        )
        .expect("encrypts")
    });
}

#[divan::bench]
fn decrypt_query_message(bencher: Bencher<'_, '_>) {
    let (key, query) = (key(), query());
    let (message, _) = sealed_query(&key, &query);
    bencher.bench_local(|| decrypt_query(&key, black_box(&message)).expect("decrypts"));
}

#[divan::bench(args = ["a", "mx", "txt_large"])]
fn encrypt_response_message(bencher: Bencher<'_, '_>, case: &str) {
    let (key, query, response) = (key(), query(), wire(case));
    let (message, _) = sealed_query(&key, &query);
    bencher
        .with_inputs(|| decrypt_query(&key, &message).expect("decrypts").1)
        .bench_local_values(|context| {
            encrypt_response(
                context,
                black_box(&response),
                response_padding(response.len()),
                &mut Fixed,
            )
            .expect("encrypts")
        });
}

#[divan::bench(args = ["a", "mx", "txt_large"])]
fn decrypt_response_message(bencher: Bencher<'_, '_>, case: &str) {
    let (key, query, response) = (key(), query(), wire(case));
    let (message, _) = sealed_query(&key, &query);
    let (_, context) = decrypt_query(&key, &message).expect("decrypts");
    let sealed = encrypt_response(
        context,
        &response,
        response_padding(response.len()),
        &mut Fixed,
    )
    .expect("encrypts");
    bencher
        .with_inputs(|| sealed_query(&key, &query).1)
        .bench_local_values(|context| {
            decrypt_response(context, black_box(&sealed)).expect("decrypts")
        });
}

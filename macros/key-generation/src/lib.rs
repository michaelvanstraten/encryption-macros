#![feature(if_let_guard)]
#![feature(let_chains)]

use proc_macro::TokenStream;
use litrs::IntegerLit;
use rand::{thread_rng, RngCore};
use hex::encode;
use quote::quote;

static DEFAULT_KEY_LENGHT : usize = 128;

#[proc_macro]
pub fn generate_key(token_stream : TokenStream) -> TokenStream {
    let key_len = match token_stream
        .into_iter()
        .collect::<Vec<_>>()
        .first() {
        Some(token) if let Ok(int_lit) = IntegerLit::try_from(token) && let Some(int) = int_lit.value::<usize>() => {
            int
        },
        _ => DEFAULT_KEY_LENGHT,
    };

    let mut key_buffer = vec![0; key_len];
    thread_rng().fill_bytes(&mut key_buffer);
    let hex_encoded_key = encode(key_buffer);
    quote! {
        #hex_encoded_key
    }.into()
}
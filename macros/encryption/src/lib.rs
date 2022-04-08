#![feature(extend_one)]
use proc_macro::{
    TokenStream,
    TokenTree,
    Group,
    Literal
};
use litrs::StringLit;
use utils::xor;
use quote::quote;

/// xor a single string literal declaratively
/// 
/// ## Example
/// ```
/// use encryption_macros::e;
/// 
/// fn main() {
///     let secret_string = e!{"piss you can not read this from the raw binary"};
///     println!("our secret string: \"{}\"", secret_string)
/// }
/// ```

#[proc_macro]
pub fn e(token_stream: TokenStream) -> TokenStream {
    let string_lit = StringLit::try_from(
        token_stream
        .into_iter()
        .collect::<Vec<_>>()
        .first()
        .expect("there is no first token in the token stream")
    ).expect("the token is not a string literal");
    generate_decode_scope(encoded_literal(string_lit.value()))
}

/// xor all string literals in the provided scope
/// 
/// ## Example 
/// ```
/// use encryption_macros::encrypt_strings;
/// 
/// encrypt_strings!{
///     fn main() {
///         println!("everything in this scope gets encrypted, {}", "even this")
///     }
/// }
/// ```

#[proc_macro]
pub fn encrypt_strings(token_stream: TokenStream) -> TokenStream {
    let mut new_stream = TokenStream::new();
    for tokentree in token_stream {
        match tokentree {
            TokenTree::Group(group) => {
                new_stream.extend_one(
                    TokenTree::from(
                        Group::new(
                            group.delimiter(), 
                            encrypt_strings(group.stream())
                        )
                    )
                );
            },
            TokenTree::Literal(literal) => {
                new_stream.extend(parse_literal(literal));
            },
            t => {
                new_stream.extend_one(t);
            }
        }
    }
    new_stream
}

/// xor all strings in a decoreded function
/// 
/// ## Example 
/// ```
/// use encryption_macros::encrypt_all_strings;
///
/// #[encrypt_all_strings]
/// fn main() {
///     println!("everything in this function gets encrypted, {}", "even this")
/// }
/// ```

#[proc_macro_attribute]
pub fn encrypt_all_strings(_metadata: TokenStream, token_stream : TokenStream) -> TokenStream {
    encrypt_strings(token_stream)
}

fn parse_literal(literal : Literal) -> TokenStream {
    let string_lit = StringLit::try_from(literal).expect("could not parse literal to string literal");
    let lit = string_lit.value();

    if lit.len() > 0 {
        let mut start = 0;
        let mut format_args = String::new();
        let mut string_literals = Vec::new();
        loop {
            if let Some(new_start) = lit[start..].find('{') {
                if let Some(end) = lit[start + new_start..].find('}') {
                    let real_start = start + new_start;
                    string_literals.push(encoded_literal(&lit[..real_start]));
                    format_args.push_str("{}");
                    format_args.push_str(&lit[real_start..real_start + end + 1]);
                    start += new_start + end + 1;
                } else {break}
            } else {break}
        };
        if start != 0 {
            quote! {
                #format_args,
                #({
                    let mut bytes = encryption_macros::decode(#string_literals).unwrap();
                    encryption_macros::xor(&mut bytes);
                    String::from_utf8(bytes).unwrap()
                }),*
            }.into()
        } else {
            generate_decode_scope(encoded_literal(lit))
        }
    } else {
        quote!{""}.into()
    }
}


fn encoded_literal(l : &str) -> String {
    let mut bytes = l.as_bytes().to_owned();
    xor(&mut bytes);
    hex::encode(bytes)
} 

fn generate_decode_scope(hex_encoded_bytes: String) -> TokenStream {
    quote!{
        {
            let mut bytes = encryption_macros::decode(#hex_encoded_bytes).unwrap();
            encryption_macros::xor(&mut bytes);
            String::from_utf8(bytes).unwrap()
        }
    }.into()
} 
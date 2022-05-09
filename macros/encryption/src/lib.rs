use encryption_macros_utils::xor;
use litrs::StringLit;
use proc_macro::{Delimiter, Group, TokenStream, TokenTree};
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
            .expect("there is no first token in the token stream"),
    )
    .expect("the token is not a string literal");
    generate_decode_scope(encoded_literal(string_lit.value())).into()
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

static FORMAT_ARGS_IDENTIFIERS: &[&'static str] = &["print", "println", "format"];

#[proc_macro]
pub fn encrypt_strings(token_stream: TokenStream) -> TokenStream {
    parse_scope(token_stream, false)
}

/// xor all strings in a decorated function
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
pub fn encrypt_all_strings(_metadata: TokenStream, token_stream: TokenStream) -> TokenStream {
    encrypt_strings(token_stream)
}

fn parse_scope(token_stream: TokenStream, mut format_arg_literal: bool) -> TokenStream {
    let mut new_stream = TokenStream::new();
    let mut token_stream = token_stream.into_iter().peekable();
    while let Some(tokentree) = token_stream.next() {
        match tokentree {
            TokenTree::Group(group) => new_stream.extend([TokenTree::from(Group::new(
                group.delimiter(),
                parse_scope(group.stream(), format_arg_literal),
            ))]),
            TokenTree::Literal(literal) => match StringLit::try_from(&literal) {
                Ok(literal) if literal.value().len() > 0 => {
                    if format_arg_literal {
                        new_stream.extend(parse_format_args_literal(literal.value()));
                        format_arg_literal = false;
                    } else {
                        new_stream.extend::<TokenStream>(
                            generate_decode_scope(encoded_literal(literal.value())).into(),
                        );
                    }
                }
                _ => new_stream.extend([TokenTree::Literal(literal)]),
            },
            TokenTree::Ident(ident)
                if FORMAT_ARGS_IDENTIFIERS.contains(&ident.to_string().as_str()) =>
            {
                if let Some(TokenTree::Punct(punct)) = token_stream.peek() {
                    if punct.as_char() == '!' {
                        format_arg_literal = true;
                    }
                }
                new_stream.extend([TokenTree::Ident(ident)])
            }
            TokenTree::Punct(punct) if punct.as_char() == '#' => {
                new_stream.extend([TokenTree::Punct(punct)]);
                match token_stream.next() {
                    Some(TokenTree::Group(group)) if group.delimiter() == Delimiter::Bracket => {
                        new_stream.extend([TokenTree::Group(group)])
                    }
                    Some(token_tree) => new_stream.extend([token_tree]),
                    None => break,
                }
            }
            t => new_stream.extend([t]),
        }
    }
    new_stream
}

fn parse_format_args_literal(literal: &str) -> TokenStream {
    let mut start = 0;
    let mut format_args = String::new();
    let mut string_literals = Vec::new();

    loop {
        if let Some(new_start) = literal[start..].find('{') {
            if let Some(end) = literal[start + new_start..].find('}') {
                let real_start = start + new_start;
                string_literals.push(encoded_literal(&literal[..real_start]));
                format_args.push_str("{}");
                format_args.push_str(&literal[real_start..real_start + end + 1]);
                start += new_start + end + 1;
            } else {
                break;
            }
        } else {
            break;
        }
    }

    if start != literal.len() - 1 {
        format_args.push_str("{}");
        string_literals.push(encoded_literal(&literal[start..]));
    }

    let decryption_scopes = string_literals
        .iter()
        .map(|string_literal| generate_decode_scope(string_literal.into()));

    quote! {
        #format_args,
        #(#decryption_scopes),*
    }
    .into()
}

fn encoded_literal(l: &str) -> String {
    let mut bytes = l.as_bytes().to_owned();
    xor(&mut bytes);
    hex::encode(bytes)
}

fn generate_decode_scope(hex_encoded_bytes: String) -> quote::__private::TokenStream {
    quote! {
        {
            let mut bytes = encryption_macros::decode(#hex_encoded_bytes).unwrap();
            encryption_macros::xor(&mut bytes);
            String::from_utf8(bytes).unwrap()
        }
    }
}

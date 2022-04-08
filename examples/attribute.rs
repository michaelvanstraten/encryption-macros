use encryption_macros::encrypt_all_strings;

#[encrypt_all_strings]
fn main() {
    let num = 2244;
    println!("everything in this function gets encrypted, {}", "even this")
}
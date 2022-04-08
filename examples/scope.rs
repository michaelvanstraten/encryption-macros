use encryption_macros::encrypt_strings;

encrypt_strings!{
    fn main() {
        println!("everything in this scope gets encrypted, {}", "even this")
    }
}
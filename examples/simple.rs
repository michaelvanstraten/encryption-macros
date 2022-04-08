use encryption_macros::e;

fn main() {
    let secret_string = e!{"piss you can not read this from the raw binary"};
    println!("our secret string: \"{}\"", secret_string)
}
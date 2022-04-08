use encryption_macros_key_generation::generate_key;
use hex::decode;

pub static ENCRYPTION_KEY_BUFFER : &'static str = generate_key!();


/// handles xoring the unencrypted and encrypted literals

pub fn xor(bytes: &mut [u8]) {
    for (b, k) in bytes.iter_mut().zip(decode(ENCRYPTION_KEY_BUFFER).unwrap()) {
        *b ^= k
    }
}

pub struct Key<'a> {
    position : usize,
    buffer : &'a [u8]
}

impl<'a> Iterator for Key<'a> {
    type Item = u8;
    fn next(&mut self) -> Option<Self::Item> {
        self.position += 1;
        if self.position > self.buffer.len() {
            self.position = 0;
        }
        return Some(self.buffer[self.position])
    }
}
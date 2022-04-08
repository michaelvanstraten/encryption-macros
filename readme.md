# encryption-marcos

This crate provides macros to XOR strings declarative or automatically at compile time and automatically decode them at run time.

The XOR key is automatically generated via a macro expansion in the utils sub-crate. 
To generate a new key just run cargo clean and recompiled the target to re-expand this macro. 

## Example 
```rust
use encryption_macros::encrypt_strings;

encrypt_strings!{
    fn main() {
        println!("everything in this scope gets encrypted, {}", "even this")
    }
}
```

## Warning

`format_args!` cannot capture variables when the format string is expanded from a macro.

So something like this: ```println!("{variable_a}")``` sadly doesn't work when inside an encrypted scope.
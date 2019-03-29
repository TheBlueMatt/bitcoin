// In general, rust is absolutely horrid at supporting users doing things like,
// for example, compiling Rust code for real environments. Disable useless lints
// that don't do anything but annoy us and cant actually ever be resolved.
#[allow(bare_trait_objects)]

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

#[no_mangle]
pub static RUST_CONSTANT: i32 = 43;

#[no_mangle]
pub extern "C" fn hello_world() {
    println!("Hello World!");
}

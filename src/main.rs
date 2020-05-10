use std::error::Error;

mod protocol;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn main() {
    println!("Hello, world!");
}

#![feature(slicing_syntax,macro_rules,associated_types)]
#![allow(dead_code)]

mod ipsec;
mod util;

mod crypto
{
    mod md5;
    mod aes;
}


const TEST_PKT : &'static [u8] = include_bytes!("test_pkt.bin");

fn main() {
    ipsec::dump_packet(TEST_PKT);
}

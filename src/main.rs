#![feature(slicing_syntax,macro_rules)]
#![allow(dead_code)]

mod ipsec;
mod util;

mod crypto
{
    mod md5;
    mod aes;
}


const TEST_PKT : &'static [u8] = include_bin!("test_pkt.bin");

fn main() {
    ipsec::dump_packet(TEST_PKT);
}

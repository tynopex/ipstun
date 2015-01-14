#![feature(slicing_syntax,int_uint)]
#![allow(dead_code,unstable)]

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

#![feature(slice_patterns,slice_bytes,num_bits_bytes,step_by)]
#![cfg_attr(test, feature(test,convert))]
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

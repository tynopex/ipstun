#![allow(dead_code)]

use std::fmt;
use std::mem;
use std::slice;


const CHUNK_SIZE: uint = 16;

struct HexDumpFmt<'a>
{
    dat: &'a [u8],
    pfx: &'a str,
    whitespace: bool,
}

impl<'a> fmt::Show for HexDumpFmt<'a>
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result
    {
        for row in self.dat.chunks(CHUNK_SIZE)
        {
            try!(write!(f, "{}", self.pfx));

            for (i,&x) in row.iter().enumerate()
            {
                if self.whitespace && i > 0
                {
                    try!(write!(f, " "));
                }

                try!(write!(f, "{:02x}", x));
            }

            if self.whitespace
            {
                try!(write!(f, "\n"));
            }
        }

        Ok(())
    }
}

pub fn hex_dump(dat: &[u8]) -> HexDumpFmt
{
    HexDumpFmt { dat: dat, pfx: "", whitespace: true }
}

pub fn hex_dump_with_prefix<'a>(dat: &'a [u8], pfx: &'a str) -> HexDumpFmt<'a>
{
    HexDumpFmt { dat: dat, pfx: pfx, whitespace: true }
}

pub fn hex_dump_nospace(dat: &[u8]) -> HexDumpFmt
{
    HexDumpFmt { dat: dat, pfx: "", whitespace: false }
}


macro_rules! get_u8_N(
    ($f:ident[$N:expr]) => (
        pub fn $f(raw: &[u8]) -> [u8,..$N]
        {
            let mut tmp: [u8,..$N] = unsafe { mem::uninitialized() };
            slice::bytes::copy_memory(&mut tmp, raw[..$N]);
            tmp
        }
    )
)

get_u8_N!(get_u8_4[4])
get_u8_N!(get_u8_8[8])
get_u8_N!(get_u8_16[16])

pub fn get_u16(raw: &[u8]) -> u16
{
    ( raw[0] as u16 <<  8 ) +
    ( raw[1] as u16       )
}

pub fn get_u32(raw: &[u8]) -> u32
{
    ( raw[0] as u32 << 24 ) +
    ( raw[1] as u32 << 16 ) +
    ( raw[2] as u32 <<  8 ) +
    ( raw[3] as u32       )
}

pub fn get_u64(raw: &[u8]) -> u64
{
    ( raw[0] as u64 << 56 ) +
    ( raw[1] as u64 << 48 ) +
    ( raw[2] as u64 << 40 ) +
    ( raw[3] as u64 << 32 ) +
    ( raw[4] as u64 << 24 ) +
    ( raw[5] as u64 << 16 ) +
    ( raw[6] as u64 <<  8 ) +
    ( raw[7] as u64       )
}


#[deriving(Show)]
pub enum PacketError
{
    InvalidPacket,
    IllegalPacket,
    TruncatedPacket,
    UnsupportedPacket,
}

pub type ParseResult<'a, T> = Result<T, PacketError>;

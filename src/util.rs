#![allow(dead_code)]

use std::fmt;


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

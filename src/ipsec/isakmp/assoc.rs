use std::fmt;
use util::{ParseResult,get_u32};
use util::PacketError::{TruncatedPacket,UnsupportedPacket};
use super::{PayloadKind};
use super::payload::{PayloadIter};


const DOI_IPSEC: u32 = 0x00000001;

const SIT_IDENTITY_ONLY: u32 = 0x00000001;


#[deriving(Copy)]
pub struct SecAssoc<'a>
{
    DOI: u32,
    Situation: u32,
    Payload: &'a [u8],
}


impl<'a> SecAssoc<'a>
{
    pub fn HeaderSize() -> uint { 8 }

    pub fn parse(dat: &[u8]) -> ParseResult<SecAssoc>
    {
        // Check size
        if dat.len() < SecAssoc::HeaderSize()
        {
            return Err(TruncatedPacket);
        }

        let sa = SecAssoc {
            DOI: get_u32(dat[0..]),
            Situation: get_u32(dat[4..]),
            Payload: dat[8..],
            };

        // Check IPSEC DOI
        if sa.DOI != DOI_IPSEC
        {
            return Err(UnsupportedPacket);
        }

        // Check Situation
        if sa.Situation != SIT_IDENTITY_ONLY
        {
            return Err(UnsupportedPacket);
        }

        Ok(sa)
    }

    pub fn iter(&self) -> PayloadIter<'a>
    {
        PayloadIter { raw: self.Payload, next_type: PayloadKind::P }
    }
}


impl<'a> fmt::Show for SecAssoc<'a>
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result
    {
        try!(write!(f, "ISAKMP::SecAssoc"));
        try!(write!(f, " DOI[IPSEC]"));
        try!(write!(f, " Sit[IDENTITY_ONLY]"));

        Ok(())
    }
}

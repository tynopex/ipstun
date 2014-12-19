use std::fmt;
use util::{ParseResult};
use util::PacketError::{TruncatedPacket,UnsupportedPacket};
use super::attr::{AttributeIter};


const KEY_IKE: u8 = 0x01;


#[deriving(Copy)]
pub struct Transform<'a>
{
    pub TransformNum: u8,
    pub TransformId: u8,

    pub Payload: &'a [u8],
}


impl<'a> Transform<'a>
{
    pub fn HeaderSize() -> uint { 2 }

    pub fn parse(dat: &[u8]) -> ParseResult<Transform>
    {
        // Check size
        if dat.len() < Transform::HeaderSize()
        {
            return Err(TruncatedPacket);
        }

        let tran = Transform {
            TransformNum: dat[0],
            TransformId: dat[1],
            Payload: dat[4..],
            };

        if tran.TransformId != KEY_IKE
        {
            return Err(UnsupportedPacket);
        }

        Ok(tran)
    }

    pub fn iter(&self) -> AttributeIter<'a>
    {
        AttributeIter { raw: self.Payload }
    }
}


impl<'a> fmt::Show for Transform<'a>
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result
    {
        try!(write!(f, "ISAKMP::Transform"));
        try!(write!(f, " TransformNum[{}]", self.TransformNum));
        try!(write!(f, " TransformId[{}]", self.TransformId));

        Ok(())
    }
}

use std::fmt;
use util::{ParseResult};
use util::PacketError::{TruncatedPacket,UnsupportedPacket};


const KEY_IKE: u8 = 0x01;


pub struct Transform<'a>
{
    pub TransformNum: u8,
    pub TransformId: u8,

    pub Payload: &'a [u8],
}


impl<'a> Transform<'a>
{
    pub fn HeaderSize() -> uint { 2 }

    pub fn parse<'a>(dat: &'a [u8]) -> ParseResult<'a, Transform>
    {
        // Check size
        if dat.len() < Transform::HeaderSize()
        {
            return Err(TruncatedPacket);
        }

        let tran = Transform {
            TransformNum: dat[0],
            TransformId: dat[1],
            Payload: dat[2..],
            };

        if tran.TransformId != KEY_IKE
        {
            return Err(UnsupportedPacket);
        }

        Ok((tran, dat[Transform::HeaderSize()..]))
    }
}


impl<'a> fmt::Show for Transform<'a>
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result
    {
        try!(write!(f, "ISAKMP::Transform"));

        Ok(())
    }
}

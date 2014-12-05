use std::fmt;
use util::{ParseResult};
use util::PacketError::{TruncatedPacket,UnsupportedPacket};
use super::{PayloadKind};
use super::payload::{PayloadIter};


const PROTO_ISAKMP: u8 = 0x01;


pub struct Proposal<'a>
{
    pub ProposalNum: u8,
    pub ProtocolId: u8,
    pub SpiSize: u8,
    pub NumTransform: u8,

    pub Payload: &'a [u8],
}


impl<'a> Proposal<'a>
{
    pub fn HeaderSize() -> uint { 4 }

    pub fn parse(dat: &[u8]) -> ParseResult<Proposal>
    {
        // Check size
        if dat.len() < Proposal::HeaderSize()
        {
            return Err(TruncatedPacket);
        }

        let prop = Proposal {
            ProposalNum: dat[0],
            ProtocolId: dat[1],
            SpiSize: dat[2],
            NumTransform: dat[3],
            Payload: dat[4..],
            };

        if prop.SpiSize > 0
        {
            return Err(UnsupportedPacket);
        }

        if prop.ProtocolId != PROTO_ISAKMP
        {
            return Err(UnsupportedPacket);
        }

        Ok(prop)
    }

    pub fn iter(&self) -> PayloadIter<'a>
    {
        PayloadIter { raw: self.Payload, next_type: PayloadKind::T }
    }
}


impl<'a> fmt::Show for Proposal<'a>
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result
    {
        try!(write!(f, "ISAKMP::Proposal"));
        try!(write!(f, " ProposalNum[{}]", self.ProposalNum));
        try!(write!(f, " ProtocolId[{}]", self.ProtocolId));
        try!(write!(f, " SpiSize[{}]", self.SpiSize));
        try!(write!(f, " NumTransform[{}]", self.NumTransform));

        Ok(())
    }
}

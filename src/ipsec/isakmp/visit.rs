use util::{ParseResult};
use util::PacketError::{UnsupportedPacket};
use super::{PayloadKind};
use super::packet::Packet;
use super::payload::Payload;
use super::vid::VendorExt;
use super::assoc::SecAssoc;
use super::proposal::Proposal;
use super::transform::Transform;
use super::attr::Attribute;


pub trait PacketVisitor
{
    fn header(&self, _: Packet) { }
    fn payload(&self, _: PayloadKind, _: Payload) { }
    fn vendor_ext(&self, _: VendorExt) { }
    fn sec_assoc(&self, _: SecAssoc) { }
    fn proposal(&self, _: Proposal) { }
    fn transform(&self, _: Transform) { }
    fn attribute(&self, _: Attribute) { }
}

fn parse_transform(v: &PacketVisitor, dat: &[u8]) -> ParseResult<()>
{
    let tran = try!(Transform::parse(dat));
    v.transform(tran);

    for x in tran.iter()
    {
        let attr = try!(x);
        v.attribute(attr);
    }

    Ok(())
}

fn parse_proposal(v: &PacketVisitor, dat: &[u8]) -> ParseResult<()>
{
    let prop = try!(Proposal::parse(dat));
    v.proposal(prop);

    for x in prop.iter()
    {
        let (ty,payl) = try!(x);
        v.payload(ty, payl);

        match ty
        {
            PayloadKind::T => { try!(parse_transform(v, payl.Payload)); }
            _ => { return Err(UnsupportedPacket); }
        }
    }

    Ok(())
}

fn parse_assoc(v: &PacketVisitor, dat: &[u8]) -> ParseResult<()>
{
    let sa = try!(SecAssoc::parse(dat));
    v.sec_assoc(sa);

    for x in sa.iter()
    {
        let (ty,payl) = try!(x);
        v.payload(ty, payl);

        match ty
        {
            PayloadKind::P => { try!(parse_proposal(v, payl.Payload)); }
            _ => { return Err(UnsupportedPacket); }
        }
    }

    Ok(())
}

fn parse_vid(v: &PacketVisitor, dat: &[u8]) -> ParseResult<()>
{
    let vid = try!(VendorExt::parse(dat));
    v.vendor_ext(vid);

    Ok(())
}

pub fn parse(v: &PacketVisitor, dat: &[u8]) -> ParseResult<()>
{
    let head = try!(Packet::parse(dat));

    v.header(head);

    for x in head.iter()
    {
        let (ty,payl) = try!(x);

        v.payload(ty, payl);

        match ty
        {
            PayloadKind::SA => { try!(parse_assoc(v, payl.Payload)); }
            PayloadKind::VID => { try!(parse_vid(v, payl.Payload)); }
            _ => { return Err(UnsupportedPacket); }
        }
    }

    Ok(())
}

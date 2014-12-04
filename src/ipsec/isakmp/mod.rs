#![allow(non_snake_case)]

use util::{hex_dump,ParseResult};
use self::packet::Packet;
use self::vid::VendorExt;
use self::assoc::SecAssoc;
use self::proposal::Proposal;
use self::transform::Transform;

mod packet;
mod payload;
mod vid;
mod assoc;
mod proposal;
mod transform;
mod attr;


#[deriving(Show)]
pub enum PayloadKind
{
    None,

    SA,         // Security Association
    P,          // Proposal
    T,          // Transform
    KE,         // Key Exchange
    ID,         // Identification
    CERT,       // Certificate
    CR,         // Certificate Request
    HASH,       // Hash
    SIG,        // Signature
    NONCE,      // Nonce
    N,          // Notification
    D,          // Delete
    VID,        // Vendor ID

    Unknown,    // Unknown
}


fn payl_kind(ty: uint) -> PayloadKind
{
    match ty
    {
         0 => PayloadKind::None,
         1 => PayloadKind::SA,
         2 => PayloadKind::P,
         3 => PayloadKind::T,
         4 => PayloadKind::KE,
         5 => PayloadKind::ID,
         6 => PayloadKind::CERT,
         7 => PayloadKind::CR,
         8 => PayloadKind::HASH,
         9 => PayloadKind::SIG,
        10 => PayloadKind::NONCE,
        11 => PayloadKind::N,
        12 => PayloadKind::D,
        13 => PayloadKind::VID,
         _ => PayloadKind::Unknown,
    }
}


fn parse_transform(dat: &[u8]) -> ParseResult<()>
{
    let (tran,_) = try!(Transform::parse(dat));
    println!("{}", tran);

    for x in tran.iter()
    {
        let attr = try!(x);

        println!("{}", attr);
    }

    Ok(((),dat[dat.len()..]))
}


fn parse_proposal(dat: &[u8]) -> ParseResult<()>
{
    let (prop,_) = try!(Proposal::parse(dat));
    println!("{}", prop);

    for x in prop.iter()
    {
        let (ty,payl) = try!(x);

        println!("{}", payl);

        match ty
        {
            PayloadKind::T => { try!(parse_transform(payl.Payload)); }
            _ => { print!("{}", hex_dump(payl.Payload)); }
        }
    }

    Ok(((),dat[dat.len()..]))
}


fn parse_assoc(dat: &[u8]) -> ParseResult<()>
{
    let (sa,_) = try!(SecAssoc::parse(dat));
    println!("{}", sa);

    for x in sa.iter()
    {
        let (ty,payl) = try!(x);

        println!("{}", payl);

        match ty
        {
            PayloadKind::P => { try!(parse_proposal(payl.Payload)); }
            _ => { print!("{}", hex_dump(payl.Payload)); }
        }
    }

    Ok(((),dat[dat.len()..]))
}


fn parse_vid(dat: &[u8]) -> ParseResult<()>
{
    let (vid,_) = try!(VendorExt::parse(dat));

    println!("{}", vid);

    Ok(((),dat[dat.len()..]))
}


fn parse_packet(dat: &[u8]) -> ParseResult<()>
{
    let (head,_) = try!(Packet::parse(dat));

    println!("{}", head);

    for x in head.iter()
    {
        let (ty,payl) = try!(x);

        println!("{}", payl);

        match ty
        {
            PayloadKind::SA => { try!(parse_assoc(payl.Payload)); }
            PayloadKind::VID => { try!(parse_vid(payl.Payload)); }
            _ => { print!("{}", hex_dump(payl.Payload)); }
        }
    }

    Ok(((),dat[dat.len()..]))
}

pub fn dump_packet(dat: &[u8])
{
    match parse_packet(dat)
    {
        Ok((_,dat)) => print!("{}", hex_dump(dat)),
        Err(_) => println!("Error"),
    }
}

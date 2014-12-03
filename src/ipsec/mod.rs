use util::hex_dump;


pub fn dump_packet(dat: &[u8])
{
    print!("{}", hex_dump(dat));
}

mod isakmp;


pub fn dump_packet(dat: &[u8])
{
    isakmp::dump_packet(dat)
}

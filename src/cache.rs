/*!
 * Routines for interacting with addresses.
 */

pub const L1D_WAYS : usize = 8;
pub const L1D_SETS : usize = 256;
pub const L1D_LINESIZE : usize = 64;

pub const L1I_WAYS : usize = 6;
pub const L1I_SETS : usize = 512;
pub const L1I_LINESIZE : usize = 64;

pub const L2_WAYS : usize = 12;
pub const L2_SETS : usize = 8192;
pub const L2_LINESIZE : usize = 128;

/// sysctl -a | grep "l2"
pub const L2_SIZE : usize = 0xC00000;

/// P-Core iCache size
pub const L1I_SIZE : usize = 0x30000;

/// How large is a page (16KB on M1)
pub const PAGE_SIZE : usize = 0x4000usize;

/// AND with this constant to get the offset within a page (for 16KB pages)
pub const PAGE_OFFSET_MASK : usize = 0x3FFFusize;

/// Same as page offset mask except include more VA bits to conflict in TLBs
pub const TLB_OFFSET_MASK : usize = 0x7FFFFFFFFFusize;

/*
For L2 cache on M1:
63               20|19          7|6           0|
+------------------+-------------+-------------+
|       Tag        |     Set     |    Offset   |
+------------------+-------------+-------------+

For M1 16KB pages:
|63                     14|13                 0|
+----------------------------------------------+
|           VPN           |       Offset       |
+----------------------------------------------+

Addresses can differ in bits [13:7] and still remain in the same page (but different sets).
There are 2^6 == 64 different cache sets contained within a page.
*/

/// Returns the L2 cache tag of a given physical address
pub fn get_cache_tag_generic(addr: u64) -> u64 {
    let set_shift = (L2_SETS as f64).log2().ceil().round() as u64;
    let offset_shift = (L2_LINESIZE as f64).log2().ceil().round() as u64;
    return (addr >> (set_shift + offset_shift));
}

/// Returns the L2 set index of a given physical address
pub fn get_cache_set_generic(addr: u64) -> u64 {
    let offset_shift = (L2_LINESIZE as f64).log2().ceil().round() as u64;
    return (addr >> offset_shift) & (L2_SETS as u64 - 1u64);
}

/// Returns the L2 cache line offset of a given physical address
pub fn get_cache_offset_generic(addr: u64) -> u64 {
    return addr & (L2_LINESIZE as u64 - 1u64);
}

/// Returns the L2 cache tag of a given physical address
/// NOTE: Only works on M1!
#[inline(always)]
pub fn get_cache_tag_m1(addr: u64) -> u64 {
    return (addr >> 20) & 0xFFFFFFFFFFF;
}

/// Returns the L2 set index of a given physical address
/// NOTE: Only works on M1!
#[inline(always)]
pub fn get_cache_set_m1(addr: u64) -> u64 {
    return (addr >> 7) & 0xFFFF;
}

/// For VIPT caches we need to make sure the virtual set index is correct too
#[inline(always)]
pub fn get_l1_cache_set_m1(addr: u64) -> u64 {
    return (addr >> 6) & 0x1FF;
}

/// Returns the L2 cache line offset of a given physical address
/// NOTE: Only works on M1!
#[inline(always)]
pub fn get_cache_offset_m1(addr: u64) -> u64 {
    return addr & 0x7F;
}

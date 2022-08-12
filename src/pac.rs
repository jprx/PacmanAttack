/*!
 * Utilities for working with pointer authentication codes (PACs)
 */

/*

This is what a PAC'ed pointer looks like:

63        56| 55 |54      47|46      0|
+-----------+----+----------+---------+
| PAC[15:5] | EL | PAC[4:0] | Address |
+-----------+----+----------+---------+

PAC[15:0]: The 16 bit pointer authentication code
Address: The rest of the address
EL: 1 for kernel pointers, 0 for user pointers

According to page D5-2656 of the ARM manual:
"The PAC field is Xn[63:56, 54:bottom_PAC_bit]."
*/

type PAC = u16;

/// Mask a kernel address with this value to eliminate the PAC
pub const PAC_BITMASK : u64 = 0xFFFF800000000000u64;

/// Number of possible PACs (2^16 on M1)
pub const NUM_PACS : usize = 0xFFFFusize;

pub const MAX_PAC : PAC = 0xFFFF;

/**
 * Returns the PAC part of a signed pointer
 */
pub fn extract_pac(signed_pointer: u64) -> PAC {
    let pac_lower = (signed_pointer >> 47) & 0x0FF;
    let pac_upper = (signed_pointer >> 56) & 0x0FF;

    return ((pac_upper << 8) | pac_lower).try_into().unwrap();
}

/**
 * Encodes a PAC into a pointer
 */
pub fn encode_pac(pac: PAC, pointer: u64) -> u64 {
    let pac_lower = (pac as u64 & 0x0FF) << 47;
    let pac_upper = ((pac as u64 >> 8) & 0x0FF) << 56;

    let pac_kernel_bit = if is_kernel_pointer(pointer) {(1 << 55)} else {0};

    return (pointer & (!PAC_BITMASK)) | pac_lower | pac_upper | pac_kernel_bit;
}

/**
 * Returns true if this is a kernel pointer (bit 52 set), false otherwise.
 */
pub fn is_kernel_pointer(addr: u64) -> bool {
    return (addr & (1 << 55)) != 0;
}

/// An iterator to try every possible PAC value for a given address
pub struct PACIterator{
    /// The current PAC value being considered
    cur_pac: PAC,

    /// Have we reported MAX_PAC yet?
    reported_last: bool,

    /// The masked pointer to use (kernel or user is fine)
    addr: u64,
}

impl Iterator for PACIterator {
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        // Whatever self.cur_pac currently is will be what we report
        let old_pac = self.cur_pac;

        if self.cur_pac == MAX_PAC {
            // If the current PAC is the max one, check if we
            // have already returned MAX_PAC before. If so, return None
            if self.reported_last {
                return None;
            }
            self.reported_last = true;
        }
        else {
            // Configure next PAC
            self.cur_pac = self.cur_pac + 1;
        }

        return Some(encode_pac(old_pac, self.addr));
    }
}

/// Get an iterator to loop over all PAC values for a given pointer
pub fn iterate_pacs(addr: u64) -> PACIterator {
    if is_kernel_pointer(addr) {
        return PACIterator{
            cur_pac: 0,
            reported_last: false,
            addr: addr | PAC_BITMASK,
        };
    }
    else {
        return PACIterator{
            cur_pac: 0,
            reported_last: false,
            addr: addr & (!PAC_BITMASK),
        };
    }
}

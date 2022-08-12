/*!
 * Routines for reading MSRs
 */
use core::arch::asm;

pub unsafe fn read_ctr_el0() -> u64 {
    let val : u64;
    asm!{
        "mrs {val}, ctr_el0",
        val = out(reg) val,
    }
    return val;
}

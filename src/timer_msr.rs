/*!
 * Utilities for reading various timers.
 *
 * Requires PACMAN patch to XNU for this to work.
 */

use crate::*;
use core::arch::asm;

/// The overhead of doing timer measurements with a NOP
/// This can be measured for your system with timer::timer_overhead()
/// Set this to 0 to ignore. This value will be different depending on if
/// you are running on a P or E core.
pub const TIMER_OVERHEAD_PCORE : u64 = 56;
pub const TIMER_OVERHEAD_ECORE : u64 = 52;

/**
 * Returns the time to access a given address using the high resolution timers
 *
 * `S3_2_c15_c0_0` == `SREG_PMC0` (Cycle Counter).
 * Assumes the Pacman kernel patches are applied such that the timers are usable from EL0.
 */
pub unsafe fn time_access(addr: u64) -> u64 {
    let t1 : u64;
    let t2 : u64;
    asm!{
        "dsb sy",
        "isb",
        "mrs {t1}, S3_2_c15_c0_0",
        "isb",
        "ldr {val_out}, [{addr}]",
        "isb",
        "mrs {t2}, S3_2_c15_c0_0",
        "isb",
        "dsb sy",
        val_out = out(reg) _,
        addr = in(reg) addr,
        t1 = out(reg) t1,
        t2 = out(reg) t2,
    }
    // Doing no load at all with 2 ISB's in between results in 56 cycles.
    // Doing only 1 ISB in between results in 28 (sometimes 26) cycles.
    return t2 - t1 - TIMER_OVERHEAD_PCORE;
}

/**
 * Returns the time to write to a given address using the high resolution timers
 *
 * `S3_2_c15_c0_0` == `SREG_PMC0` (Cycle Counter).
 * Assumes the Pacman kernel patches are applied such that the timers are usable from EL0.
 */
 pub unsafe fn time_store(addr: u64) -> u64 {
    let t1 : u64;
    let t2 : u64;
    let val_in : u64 = 0x3131313131313131;
    asm!{
        "dsb sy",
        "isb",
        "mrs {t1}, S3_2_c15_c0_0",
        "isb",
        "str {val_in}, [{addr}]",
        "isb",
        "mrs {t2}, S3_2_c15_c0_0",
        "isb",
        "dsb sy",
        val_in = in(reg) val_in,
        addr = in(reg) addr,
        t1 = out(reg) t1,
        t2 = out(reg) t2,
    }
    // Doing no load at all with 2 ISB's in between results in 56 cycles.
    // Doing only 1 ISB in between results in 28 (sometimes 26) cycles.
    return t2 - t1 - TIMER_OVERHEAD_PCORE;
}

/**
 * Returns the time to execute a given address using the high resolution timers
 *
 * `S3_2_c15_c0_0` == `SREG_PMC0` (Cycle Counter).
 * Assumes the Pacman kernel patches are applied such that the timers are usable from EL0.
 */
 pub unsafe fn time_exec(addr: u64) -> u64 {
    let t1 : u64;
    let t2 : u64;
    asm!{
        "dsb sy",
        "isb",
        "mrs {t1}, S3_2_c15_c0_0",
        "isb",
        "blr {addr}",
        "isb",
        "mrs {t2}, S3_2_c15_c0_0",
        "isb",
        "dsb sy",
        addr = in(reg) addr,
        t1 = out(reg) t1,
        t2 = out(reg) t2,
    }
    // Doing no load at all with 2 ISB's in between results in 56 cycles.
    // Doing only 1 ISB in between results in 28 (sometimes 26) cycles.
    return t2 - t1 - TIMER_OVERHEAD_PCORE;
}

/**
 * Returns the constant time offset associated with performing measurements.
 * This number can be measured for a platform and then treated as a constant.
 */
pub fn timer_overhead() -> u64 {
    let t1 : u64;
    let t2 : u64;
    let val_out : u64;
    unsafe {
        asm!{
            "isb",
            "mrs {t1}, S3_2_c15_c0_0",
            "isb",
            "nop", // Do a NOP instead of a LDR here
            "isb",
            "mrs {t2}, S3_2_c15_c0_0",
            "isb",
            t1 = out(reg) t1,
            t2 = out(reg) t2,
        }
    }
    return t2 - t1;
}

/**
 * Reports the time for a cache miss.
 *
 * # Arguments
 * * `untouched_page`: A page that has been allocated but never written to/ read from
 *   (and is therefore not present in the TLB).
 *
 * # Return Value
 * Returns the number of cycles on a cache miss as reported by `timer::time_access`.
 *
 * # Side Effects
 * Will load several addresses from the page.
 *
 * # References
 * See 'Branch Different' by Hetterich and Schwarz Section 3.2 Listing 1.
 */
pub fn time_miss(untouched_page: &mut [u8]) -> u64 {
    unsafe {
        time_access(&untouched_page[0] as *const u8 as u64);
        return time_access(&untouched_page[cache::L2_LINESIZE * 3] as *const u8 as u64);
    }
}

/**
 * Reports the time for a cache hit.
 *
 * # Arguments
 * * `page`: A page that can be read from.
 *
 * # Return Value
 * Returns the number of cycles on a cache hit as reported by `timer::time_access`.
 *
 * # Side Effects
 * Will load several addresses from the page.
 *
 * # References
 * See 'Branch Different' by Hetterich and Schwarz Section 3.2 Listing 1.
 */
pub fn time_hit(page: &mut [u8]) -> u64 {
    unsafe {
        time_access(&page[0] as *const u8 as u64);
        return time_access(&page[0] as *const u8 as u64);
    }
}
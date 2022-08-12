/*!
 * It's timer_msr except using the counter.rs multithreaded counter as a timer.
 */

use crate::*;
use core::arch::asm;

/// TODO: Remove these from here
// These are here because pacmankit kindly subtracts the timer overhead when reporting MSR reads from the kernel.
// These are strictly a timer_msr thing so they do not belong here. We don't track overheads in this timer module as the
// multithread timer has lots of variance and isn't super precise. We keep these equal to the value in timer_msr.rs
// so that when doing timing with the multithreaded timer in userspace, the kernel overhead is still taken care of.
// This will be resolved when we refactor the code.
pub const TIMER_OVERHEAD_PCORE : u64 = 56;
pub const TIMER_OVERHEAD_ECORE : u64 = 52;

/**
 * Returns the time to access a given address using the counter thread.
 */
pub unsafe fn time_access(addr: u64) -> u64 {
    let t1 : u64;
    let t2 : u64;
    asm!{
        "dsb sy",
        "isb",
        "ldr {t1}, [{cnt_addr}]",
        "isb",
        "ldr {val_out}, [{addr}]",
        "isb",
        "ldr {t2}, [{cnt_addr}]",
        "isb",
        "dsb sy",
        val_out = out(reg) _,
        addr = in(reg) addr,
        cnt_addr = in(reg) &mut counter::CTR as *mut u64 as u64,
        t1 = out(reg) t1,
        t2 = out(reg) t2,
    }
    return t2 - t1;
}

/**
 * Returns the time to write to a given address using the thread counter.
 */
 pub unsafe fn time_store(addr: u64) -> u64 {
    let t1 : u64;
    let t2 : u64;
    let val_in : u64 = 0x3131313131313131;
    asm!{
        "dsb sy",
        "isb",
        "ldr {t1}, [{cnt_addr}]",
        "isb",
        "str {val_in}, [{addr}]",
        "isb",
        "ldr {t2}, [{cnt_addr}]",
        "isb",
        "dsb sy",
        val_in = in(reg) val_in,
        addr = in(reg) addr,
        cnt_addr = in(reg) &mut counter::CTR as *mut u64 as u64,
        t1 = out(reg) t1,
        t2 = out(reg) t2,
    }
    return t2 - t1;
}

/**
 * Returns the time to execute a given address using the thread counter.
 */
 pub unsafe fn time_exec(addr: u64) -> u64 {
    let t1 : u64;
    let t2 : u64;
    asm!{
        "dsb sy",
        "isb",
        "ldr {t1}, [{cnt_addr}]",
        "isb",
        "blr {addr}",
        "isb",
        "ldr {t2}, [{cnt_addr}]",
        "isb",
        "dsb sy",
        addr = in(reg) addr,
        cnt_addr = in(reg) &mut counter::CTR as *mut u64 as u64,
        t1 = out(reg) t1,
        t2 = out(reg) t2,
    }
    return t2 - t1;
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
            "ldr {t1}, [{cnt_addr}]",
            "isb",
            "nop", // Do a NOP instead of a LDR here
            "isb",
            "ldr {t2}, [{cnt_addr}]",
            "isb",
            cnt_addr = in(reg) &mut counter::CTR as *mut u64 as u64,
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
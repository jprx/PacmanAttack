/*!
 * A dedicated thread for measuring a variable that just counts up.
 *
 * Surprisingly useful for observing the effects of time (so long
 * as all measurements include a serializing sync barrier instruction!)
 */

use crate::*;

/**
 * A globally visible counter that can be sampled to get a rough measurement of how far time has passed.
 *
 * Don't forget to synchronize before sampling!
 */
pub static mut CTR : u64 = 0;

/**
 * Continuously increment the counter variable to get a sense of how much time has passed.
 */
pub unsafe fn counter_thread() {
    if !set_core(CoreKind::PCORE) {
        println!("Error setting CPU affinity!");
        return;
    }
    loop {
        // write_volatile(&mut CTR, read_volatile(&CTR) + 1);
        asm!{
            "eor x0, x0, x0",
            "1:",
            "str x0, [{cnt_addr}]",
            "add x0, x0, 1",
            "b 1b",
            cnt_addr = in(reg) &mut counter::CTR as *mut u64 as u64,
        }
    }
}

/**
 * Sample the current counter value. Handles all synchronization as appropriate.
 *
 * DEPRECATED- DO NOT USE
 * See timer_multithread.rs instead.
 */
#[inline(always)]
pub unsafe fn read_counter() -> u64 {
    asm!{
        "isb"
    }
    let retval = read_volatile(&CTR);
    asm!{
        "isb"
    }

    return retval;
}

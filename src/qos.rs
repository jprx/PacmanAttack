//! Utilities for pinning a thread to a particular kind of core (P or E core)
use core::arch::asm;

// sys/qos.h
/**
 * Constants for the different kinds of cores on M1.
 */
#[repr(u64)]
pub enum CoreKind {
    PCORE = 0x21, // QOS_CLASS_USER_INTERACTIVE
    ECORE = 0x09, // QOS_CLASS_BACKGROUND
}

// See pthread/qos.h
#[link(name = "system")]
extern "C" {
    #[doc(hidden)]
    pub fn pthread_set_qos_class_self_np(flavor: CoreKind, priority: u64) -> i32;
}

/**
 * Switches the current process onto a different core.
 *
 * # Arguments
 * * `kind`: Which kind of core do we want to run on?
 *
 * # Return Value
 * Returns `true` on success, `false` on failure.
 */
pub unsafe fn set_core(kind: CoreKind) -> bool {
    return 0 == pthread_set_qos_class_self_np(kind, 0);
}

/**
 * Returns the current core we are operating on.
 *
 * Has nothing to do with the pthread qos libraries, but it fits the theme of
 * "select a core" so it goes here.
 *
 * # Return Value
 * An integer representing the current core. If this value changes, you switched cores.
 */
pub fn core_id() -> u64 {
    unsafe {
        let cur_core : u64;
        asm!{
            "mrs {cur_core}, TPIDRRO_EL0",
            cur_core = out(reg) cur_core,
        }
        return cur_core & 0x07;
    }
}

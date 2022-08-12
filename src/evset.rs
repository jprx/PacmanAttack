/*!
 * Generate eviction sets for data / inst pointers
 */

use crate::*;
use rand::prelude::SliceRandom;

/// What stride do we take between virtual addresses to generate out evset candidates?
/// If this is a large power of two multiple of page size, it will increase the likelihood of TLB conflicts.
/// To eliminate TLB conflicts, make this a large power of 2 + 1 multiple of page size.
pub const STRIDE : usize = 4096 * cache::PAGE_SIZE;

pub const EVSET_SIZE_MAX : usize = 1024;

/**
 * Create a data eviction set within a kernel memory region for a given physical address.
 *
 * `target_paddr` should be a physical address.
 *
 * # Arguments
 * * `target_vaddr`: The virtual address to create an eviction set for.
 * * `target_paddr`: The physical address corresponding to `target_vaddr`.
 *                   (can't just compute this as we don't know which address space the target vaddr comes from).
 * * `kernel_memory`: The kernel memory region to draw addresses from for the eviction set.
 * * `kernel_memory_size`: The size of `kernel_memory`.
 *
 * # Return Value
 * A vector of addresses within `kernel_memory` that will contend with `target_paddr`.
 */
 pub unsafe fn data_kpevset(target_vaddr: u64, target_paddr: u64, kernel_memory: u64, kernel_memory_size: usize) -> Vec<u64> {
    let handle = match PacmanKitConnection::init() {
        Some(v) => v,
        None => panic!("Couldn't connect to PacmanKit"),
    };

    let mut vec = Vec::new();
    let target_l2_set = cache::get_cache_set_m1(target_paddr);

    // Offset applies to virtual addresses
    let memory_region_addr = kernel_memory as usize;

    for i in (0..kernel_memory_size).step_by(128) {
        let idx = i;
        if idx > kernel_memory_size {
            println!("0x{:X}: Out of memory", idx);
            break;
        }

        let cur_va = kernel_memory + idx as u64;
        let cur_pa = handle.kernel_virt_to_phys(cur_va).unwrap();
        // if cache::get_cache_set_m1(cur_va) == cache::get_cache_set_m1(target_vaddr) {
            if cache::get_cache_set_m1(cur_pa) == target_l2_set {
                vec.push(cur_va);
            }
        // }
    }

    let virt_set_index = cache::get_l1_cache_set_m1(target_vaddr);
    for i in &vec {
        if cache::get_l1_cache_set_m1(*i) != virt_set_index {
            panic!("Incongruent VAs");
        }
    }

    return vec;
}

/**
 * Create a data eviction set within a memory region for a given physical address.
 *
 * `target_paddr` should be a physical address.
 *
 * # Arguments
 * * `target_vaddr`: The virtual address to create an eviction set for.
 * * `target_paddr`: The physical address corresponding to `target_vaddr`.
 *                   (can't just compute this as we don't know which address space the target vaddr comes from).
 * * `memory_region`: The region to draw addresses from for the eviction set.
 *
 * # Return Value
 * A vector of addresses within `memory_region` that will contend with `target_paddr`.
 */
pub unsafe fn data_pevset(target_vaddr: u64, target_paddr: u64, memory_region: &mut [u8]) -> Vec<u64> {
    let handle = match PacmanKitConnection::init() {
        Some(v) => v,
        None => panic!("Couldn't connect to PacmanKit"),
    };

    let mut vec = Vec::new();
    let target_l2_set = cache::get_cache_set_m1(target_paddr);

    // Offset applies to virtual addresses
    let memory_region_addr = memory_region.as_ptr() as usize;
    let offset = (target_vaddr as usize) & cache::TLB_OFFSET_MASK;

    for i in (0..memory_region.len()).step_by(evset::STRIDE) {
        let idx = i + offset;
        if idx > memory_region.len() { break; }

        if vec.len() >= EVSET_SIZE_MAX { break; }

        let cur_va = &memory_region[idx] as *const u8 as u64;

        // Uncomment this to use physical translation:
        // For now we do NOT use physical translation as we don't need it
        // let cur_pa = handle.user_virt_to_phys(cur_va).unwrap();
        // if cache::get_cache_set_m1(cur_pa) == target_l2_set {
            vec.push(cur_va);
        // }
    }

    let virt_set_index = cache::get_l1_cache_set_m1(target_vaddr);
    for i in &vec {
        if cache::get_l1_cache_set_m1(*i) != virt_set_index {
            // panic!("Incongruent VAs");
        }
    }

    return vec;
}

/**
 * Create an instruction eviction set within a memory region for a given physical address.
 *
 * `target_paddr` should be a physical address.
 *
 * # Arguments
 * * `target_vaddr`: The virtual address to create an eviction set for.
 * * `target_paddr`: The physical address corresponding to `target_vaddr`.
 *                   (can't just compute this as we don't know which address space the target vaddr comes from).
 *
 * # Return Value
 * A vector of addresses within `memory_region` that will contend with `target_paddr`.
 *
 * # Side Effects
 * Will make parts of memory_region executable, and fill them with instructions to execute.
 */
pub unsafe fn inst_pevset(target_vaddr: u64, target_paddr: u64, memory_region: &mut [u8]) -> Vec<u64> {
    let evset = data_pevset(target_vaddr, target_paddr, memory_region);

    for entry in &evset {
        let pg = core::slice::from_raw_parts_mut(*entry as *mut u8, cache::PAGE_SIZE);
        retpoline::mk_retpoline_page(pg).unwrap();
    }

    return evset;
}

/**
 * Create an eviction set for a given data address within a memory region.
 *
 * `addr` may be contained within `memory_region`.
 *
 * # Arguments
 * * `addr`: The address to create an eviction set for.
 * * `memory_region`: A memory region to pick addresses from to create the eviction set.
 *
 * # Return Value
 * A vector of addresses within `memory_region`.
 */
pub fn data_evset(addr: *const u8, memory_region: &mut [u8]) -> Vec<*mut u8> {
    let mut vec = Vec::new();
    let ptr = addr as u64;
    let memory_region_base = (&memory_region[0] as *const u8) as u64;

    for i in 0..L1D_WAYS {
        let offset = ((i + 1) * L1D_SETS * L1D_LINESIZE) << 2;

        if offset > memory_region.len() {
            panic!("Cannot create a data eviction set! Out of memory!");
        }

        let new_evset_entry = memory_region_base + (offset as u64);
        vec.push(new_evset_entry as *mut u8);
    }

    vec.shuffle(&mut thread_rng());

    return vec;
}

/**
 * Create an eviction set for a given instruction address within a memory region.
 *
 * `addr` may be contained within `memory_region`.
 *
 * Note: The regions are treated as instruction slices (not data slices) and hence
 * act as pointers to 32 bit values instead of 8 bit values.
 *
 * # Arguments
 * * `addr`: The address to create an eviction set for.
 * * `memory_region`: A memory region to pick addresses from to create the eviction set.
 *
 * # Return Value
 * A vector of addresses within `memory_region`.
 */
pub fn inst_evset(addr: *const u32, memory_region: &mut [u32]) -> Vec<*mut u32> {
    let mut vec = Vec::new();
    let ptr = addr as u64;
    let memory_region_base = (&memory_region[0] as *const u32) as u64;

    for i in 0..L1I_WAYS {
        let offset = (i + 1) * L1I_SETS * L1I_LINESIZE;

        if offset > memory_region.len() / 4 {
            panic!("Cannot create a data eviction set! Out of memory!");
        }

        let new_evset_entry = memory_region_base + (offset as u64);
        vec.push(new_evset_entry as *mut u32);
    }

    vec.shuffle(&mut thread_rng());

    return vec;
}

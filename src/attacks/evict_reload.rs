/*!
 * Generate latency traces for graphing and precise timer metrics using evict+reload.
 */
use crate::*;
use rand::thread_rng;
use rand::prelude::SliceRandom;

/// Number of different eviction set sizes to try (each trial == a different eviction size)
pub const TRIALS : usize = 256;

/// Number of times to try a random collection of addresses from the potential eviction set for a given size
pub const NUM_RETRIALS : usize = 25;

/// How many times to repeat a trial before reporting a latency
pub const TRIAL_REPEAT : usize = 12;

/**
 * Evict+Reload for data accesses.
 *
 * TLDR:
 * ```
 * for num_test_addrs in range(TRIALS):
 *    for retrial_idx in range(NUM_RETRIALS):
 *        chosen = evset.sample(num_test_addrs)
 *
 *        for cur_trial in range(TRIAL_REPEAT):
 *            load test addr
 *            load chosen set in random order
 *            reload test addr
 *            record reload latency
 *
 *    print(average(reload latencies for a given trial size))
 * ```
 */
pub unsafe fn data_evict_reload(shared_mem: &mut [u8]) {
    let handle = match PacmanKitConnection::init() {
        Some(v) => v,
        None => panic!("Couldn't connect to PacmanKit"),
    };

    let mut kernel_mmap_va = match handle.kernel_mmap() {
        Ok(v) => v,
        Err(err) => panic!("Couldn't call IOMalloc in the kernel!"),
    };

    let kernel_mmap_pa = handle.kernel_virt_to_phys(kernel_mmap_va).unwrap();
    let target_set = cache::get_cache_set_m1(kernel_mmap_pa);
    println!("Kernel mmap VA: 0x{:X}\n            PA: 0x{:X}\n", kernel_mmap_va, kernel_mmap_pa);
    println!("Generating eviction set to match address with L2 set {}...", target_set);

    let evset = data_pevset(kernel_mmap_va, kernel_mmap_pa, shared_mem);
    println!("Found {} conflicts.", evset.len());

    // Evict + Reload
    for num_test_addrs in 0..TRIALS {
        let mut averages = [0; NUM_RETRIALS];
        let mut trial_accumulator = 0;
        for retrial_idx in 0..NUM_RETRIALS {
            // Chose an eviction set of size `num_test_addrs`...
            let mut chosen : Vec<u64> = evset.choose_multiple(&mut rand::thread_rng(), num_test_addrs + 1).into_iter().cloned().collect();
            let evict_me = chosen.pop().unwrap();

            // ...and access them in a random order
            // Don't do pointer chasing as the DMP can predict that
            // Instead just index the vector randomly
            let mut indexes : Vec<usize> = (0..chosen.len()).collect();
            indexes.shuffle(&mut thread_rng());

            let mut measurements = [0; TRIAL_REPEAT];

            for cur_trial in 0..TRIAL_REPEAT+1 {
                let init_read_time = timer::time_access(evict_me);

                for i in 0..num_test_addrs {
                    timer::time_access(chosen[indexes[i]]);
                }

                let reload_time = timer::time_access(evict_me);

                // Skip the very first trial as its latency is always way too high
                if cur_trial != 0 {
                    measurements[cur_trial - 1] = reload_time;
                }
            }

            let mut average : u64 = 0;
            for i in 0..TRIAL_REPEAT {
                average += measurements[i];
            }
            average /= (TRIAL_REPEAT as u64);
            trial_accumulator += average;
            averages[retrial_idx] = average;
        }
        print!("'{}': [", num_test_addrs);

        for i in averages {
            print!("{},", i);
        }

        println!("],");
    }
}

/**
 * Evict+Reload for instruction accesses.
 *
 * TLDR:
 * ```
 * for num_test_addrs in range(TRIALS):
 *    for retrial_idx in range(NUM_RETRIALS):
 *        chosen = evset.sample(num_test_addrs)
 *
 *        for cur_trial in range(TRIAL_REPEAT):
 *            execute test addr
 *            execute chosen set in random order
 *            execute (again) test addr
 *            record execute latency
 *
 *    print(average(execute latencies for a given trial size))
 * ```
 */
 pub unsafe fn inst_evict_reload(shared_mem: &mut [u8]) {
    let handle = match PacmanKitConnection::init() {
        Some(v) => v,
        None => panic!("Couldn't connect to PacmanKit"),
    };

    let mut kernel_mmap_va = match handle.kernel_mmap() {
        Ok(v) => v,
        Err(err) => panic!("Couldn't call IOMalloc in the kernel!"),
    };

    let kernel_mmap_pa = handle.kernel_virt_to_phys(kernel_mmap_va).unwrap();
    let target_set = cache::get_cache_set_m1(kernel_mmap_pa);
    println!("Kernel mmap VA: 0x{:X}\n            PA: 0x{:X}\n", kernel_mmap_va, kernel_mmap_pa);
    println!("Generating eviction set to match address with L2 set {}...", target_set);

    let evset = inst_pevset(kernel_mmap_va, kernel_mmap_pa, shared_mem);
    println!("Found {} conflicts.", evset.len());

    // Evict + Reload
    for num_test_addrs in 0..TRIALS {
        let mut averages = [0; NUM_RETRIALS];
        let mut trial_accumulator = 0;
        for retrial_idx in 0..NUM_RETRIALS {
            // init_memory(shared_mem);

            // Chose an eviction set of size `num_test_addrs`...
            let mut chosen : Vec<u64> = evset.choose_multiple(&mut rand::thread_rng(), num_test_addrs + 1).into_iter().cloned().collect();
            let evict_me = chosen.pop().unwrap();

            // ...and access them in a random order
            // Don't do pointer chasing as the DMP can predict that
            // Instead just index the vector randomly
            let mut indexes : Vec<usize> = (0..chosen.len()).collect();
            indexes.shuffle(&mut thread_rng());

            let mut measurements = [0; TRIAL_REPEAT];

            for cur_trial in 0..TRIAL_REPEAT+1 {
                let init_read_time = timer::time_exec(evict_me);

                for i in 0..num_test_addrs {
                    timer::time_exec(chosen[indexes[i]]);
                }

                let reload_time = timer::time_exec(evict_me);

                // Skip the very first trial as its latency is always way too high
                if cur_trial != 0 {
                    measurements[cur_trial - 1] = reload_time;
                }
            }

            let mut average : u64 = 0;
            for i in 0..TRIAL_REPEAT {
                average += measurements[i];
            }
            average /= (TRIAL_REPEAT as u64);
            trial_accumulator += average;
            averages[retrial_idx] = average;
        }
        print!("'{}': [", num_test_addrs);

        for i in averages {
            print!("{},", i);
        }

        println!("],");
    }
}

/**
 * Evict+Reload for data accesses in the kernel.
 *
 * Keep this in sync with `data_evict_reload`!
 */
 pub unsafe fn data_evict_reload_kernel(shared_mem: &mut [u8]) {
    let handle = match PacmanKitConnection::init() {
        Some(v) => v,
        None => panic!("Couldn't connect to PacmanKit"),
    };

    let kernel_target_va = handle.leak_limit_location().unwrap();
    // let kernel_target_va = handle.kernel_mmap().unwrap();
    let kernel_target_pa = handle.kernel_virt_to_phys(kernel_target_va).unwrap();

    let target_set = cache::get_cache_set_m1(kernel_target_pa);
    println!("Kernel target VA: 0x{:X}\n              PA: 0x{:X}\n              Contents: 0x{:X}\n", kernel_target_va, kernel_target_pa, handle.kernel_read(kernel_target_va).unwrap());
    println!("Generating eviction set to match address with L2 set {}...", target_set);

    let evset = data_pevset(kernel_target_va, kernel_target_pa, shared_mem);
    println!("Found {} conflicts.", evset.len());

    // Evict + Reload
    for num_test_addrs in 0..evset.len() {
        let mut averages = [0; NUM_RETRIALS];
        let mut trial_accumulator = 0;
        for retrial_idx in 0..NUM_RETRIALS {
            // Chose an eviction set of size `num_test_addrs`...
            let mut chosen : Vec<u64> = evset.choose_multiple(&mut rand::thread_rng(), num_test_addrs + 1).into_iter().cloned().collect();

            // For the user mode version, we use something from the evset as our reload target
            // Since we're using the kernel, we can ignore this popped value
            // Keep it here to ensure the index math lines up with the user version of this method, though.
            let ignore_this = chosen.pop().unwrap();

            // ...and access them in a random order
            // Don't do pointer chasing as the DMP can predict that
            // Instead just index the vector randomly
            let mut indexes : Vec<usize> = (0..chosen.len()).collect();
            indexes.shuffle(&mut thread_rng());

            let mut measurements = [0; TRIAL_REPEAT];

            for cur_trial in 0..TRIAL_REPEAT+1 {
                let init_read_time = handle.kernel_read_for_timing(kernel_target_va, true).unwrap();

                for i in 0..num_test_addrs {
                    timer::time_access(chosen[indexes[i]]);
                }

                let reload_time = handle.kernel_read_for_timing(kernel_target_va, true).unwrap();

                // Skip the very first trial as its latency is always way too high
                if cur_trial != 0 {
                    measurements[cur_trial - 1] = reload_time;
                }
            }

            let mut average : u64 = 0;
            for i in 0..TRIAL_REPEAT {
                average += measurements[i];
            }
            average /= (TRIAL_REPEAT as u64);
            trial_accumulator += average;
            averages[retrial_idx] = average;
        }
        print!("'{}': [", num_test_addrs);

        for i in averages {
            print!("{},", i);
        }

        println!("],");
    }
}

/**
 * Evict+Reload for instruction accesses.
 *
 * Keep this in sync with `inst_evict_reload`!
 */
 pub unsafe fn inst_evict_reload_kernel(shared_mem: &mut [u8]) {
    let handle = match PacmanKitConnection::init() {
        Some(v) => v,
        None => panic!("Couldn't connect to PacmanKit"),
    };

    let kernel_method_va = handle.leak_retpoline().unwrap() | PAC_BITMASK; // + 0x30C0;
    // let kernel_method_va = handle.get_kernel_base().unwrap() + attacks::pacman::INST_TARGET_OFFSET;

    let kernel_method_pa = handle.kernel_virt_to_phys(kernel_method_va).unwrap();
    let target_set = cache::get_cache_set_m1(kernel_method_pa);
    println!("Kernel mmap VA: 0x{:X}\n            PA: 0x{:X}\n", kernel_method_va, kernel_method_pa);
    println!("Generating eviction set to match address with L2 set {}...", target_set);

    let evset = inst_pevset(kernel_method_va, kernel_method_pa, shared_mem);
    println!("Found {} conflicts.", evset.len());

    // Evict + Reload
    for num_test_addrs in 0..TRIALS {
        let mut averages = [0; NUM_RETRIALS];
        let mut trial_accumulator = 0;
        for retrial_idx in 0..NUM_RETRIALS {
            // init_memory(shared_mem);

            // Chose an eviction set of size `num_test_addrs`...
            let mut chosen : Vec<u64> = evset.choose_multiple(&mut rand::thread_rng(), num_test_addrs + 1).into_iter().cloned().collect();

            // For the user mode version, we use something from the evset as our reload target
            // Since we're using the kernel, we can ignore this popped value
            // Keep it here to ensure the index math lines up with the user version of this method, though.
            let ignore_this = chosen.pop().unwrap();

            // ...and access them in a random order
            // Don't do pointer chasing as the DMP can predict that
            // Instead just index the vector randomly
            let mut indexes : Vec<usize> = (0..chosen.len()).collect();
            indexes.shuffle(&mut thread_rng());

            let mut measurements = [0; TRIAL_REPEAT];

            for cur_trial in 0..TRIAL_REPEAT+1 {
                let init_read_time = handle.kernel_exec_for_timing(kernel_method_va, true).unwrap();

                for i in 0..num_test_addrs {
                    timer::time_exec(chosen[indexes[i]]);
                }

                let reload_time = handle.kernel_exec_for_timing(kernel_method_va, true).unwrap();

                // Skip the very first trial as its latency is always way too high
                if cur_trial != 0 {
                    measurements[cur_trial - 1] = reload_time;
                }
            }

            let mut average : u64 = 0;
            for i in 0..TRIAL_REPEAT {
                average += measurements[i];
            }
            average /= (TRIAL_REPEAT as u64);
            trial_accumulator += average;
            averages[retrial_idx] = average;
        }
        print!("'{}': [", num_test_addrs);

        for i in averages {
            print!("{},", i);
        }

        println!("],");
    }
}

/**
 * Evict+Reload for data accesses in the kernel using an eviction set also in the kernel.
 *
 * This is mostly useful for testing.
 *
 * Keep this in sync with `data_evict_reload`!
 */
 pub unsafe fn data_evict_reload_kernel_kernel_evset(shared_mem: &mut [u8]) {
    let handle = match PacmanKitConnection::init() {
        Some(v) => v,
        None => panic!("Couldn't connect to PacmanKit"),
    };

    let kernel_limit_addr = handle.leak_limit_location().unwrap();
    let kernel_mmap_addr = handle.kernel_mmap().unwrap();
    let kernel_target_va = kernel_limit_addr;
    // let kernel_target_va = kernel_mmap_addr;
    let kernel_target_pa = handle.kernel_virt_to_phys(kernel_target_va).unwrap();

    let target_set = cache::get_cache_set_m1(kernel_target_pa);
    println!("Kernel target VA: 0x{:X}\n              PA: 0x{:X}\n              Contents: 0x{:X}\n", kernel_target_va, kernel_target_pa, handle.kernel_read(kernel_target_va).unwrap());
    println!("Generating eviction set to match address with L2 set {}...", target_set);

    // let evset = data_pevset(kernel_target_va, kernel_target_pa, shared_mem);
    let evset = data_kpevset(kernel_target_va, kernel_target_pa, kernel_mmap_addr, 0xC000 * cache::PAGE_SIZE);
    println!("Found {} conflicts.", evset.len());

    for i in 0..evset.len() {
        if i > 100 {break;}
        let print_va = evset[i];
        println!("0x{:X}\t=>\t0x{:X}", print_va, handle.kernel_virt_to_phys(print_va).unwrap());
    }

    // Evict + Reload
    for num_test_addrs in 0..evset.len() {
        let mut averages = [0; NUM_RETRIALS];
        let mut trial_accumulator = 0;
        for retrial_idx in 0..NUM_RETRIALS {
            // Chose an eviction set of size `num_test_addrs`...
            let mut chosen : Vec<u64> = evset.choose_multiple(&mut rand::thread_rng(), num_test_addrs + 1).into_iter().cloned().collect();

            // For the user mode version, we use something from the evset as our reload target
            // Since we're using the kernel, we can ignore this popped value
            // Keep it here to ensure the index math lines up with the user version of this method, though.
            let ignore_this = chosen.pop().unwrap();

            // ...and access them in a random order
            // Don't do pointer chasing as the DMP can predict that
            // Instead just index the vector randomly
            let mut indexes : Vec<usize> = (0..chosen.len()).collect();
            indexes.shuffle(&mut thread_rng());

            let mut measurements = [0; TRIAL_REPEAT];

            for cur_trial in 0..TRIAL_REPEAT+1 {
                let init_read_time = handle.kernel_read_for_timing(kernel_target_va, true).unwrap();

                for i in 0..num_test_addrs {
                    // timer::time_access(chosen[indexes[i]]);
                    handle.kernel_read_for_timing(chosen[indexes[i]], true).unwrap();
                }

                // Flush the entire cache:
                // init_memory(shared_mem);
                // flush_cache(shared_mem);

                let reload_time = handle.kernel_read_for_timing(kernel_target_va, true).unwrap();

                // Skip the very first trial as its latency is always way too high
                if cur_trial != 0 {
                    measurements[cur_trial - 1] = reload_time;
                }
            }

            let mut average : u64 = 0;
            for i in 0..TRIAL_REPEAT {
                average += measurements[i];
            }
            average /= (TRIAL_REPEAT as u64);
            trial_accumulator += average;
            averages[retrial_idx] = average;
        }
        print!("'{}': [", num_test_addrs);

        for i in averages {
            print!("{},", i);
        }

        println!("],");
    }
}

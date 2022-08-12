/*!
 * Wrapper to activate the kernel read/ write bug we assume we have.
 *
 * DEPRECATED in favor of the PacmanKit kext (see pacmankit.rs).
 */
use crate::*;

pub const KERNEL_PID : u64 = 0;

pub const SYS_KAS_INFO : u64 = 439u64;

/**
 * Returns the kernel slide using kas_info (#439)
 *
 * Not currently working- we lack the entitlement required to run!
 */
pub unsafe fn sys_kas_info() -> usize {
    // KAS_INFO_KERNEL_TEXT_SLIDE_SELECTOR
    let selector : u64 = 0;

    let mut val : u64 = 0;
    let mut sz : u64 = 8;

    let retval : KernReturn;

    asm!{
        "svc #0",
        in("x0") selector,
        in("x1") &mut val as *mut u64,
        in("x2") &mut sz as *mut u64,
        in("x8") SYS_KAS_INFO,
        in("x16") SYS_KAS_INFO,
        lateout("x0") retval,
    }

    if retval != KERN_SUCCESS {
        println!("Warning- kas_info failed!");
    }

    return val as usize;
}

/**
 * Reads a virtual address from the kernel.
 *
 * Here we use a patched kernel to get tfp0 and
 * use it to read from kernel memory with the mach vm API.
 *
 * A real attacker would replace this with their memory corruption bug of choice.
 */
pub unsafe fn kern_read(addr: usize) -> Option<u64> {
    let mut kernel_task_port : MachPort = 0;

    match task_for_pid(mach_task_self(), KERNEL_PID, &mut kernel_task_port) {
        KERN_SUCCESS => {},
        err => {
            println!("Error aquiring the kernel task port. Did you forget to run as root? Error string: Error code 0x{:X} ({:?})", err, std::ffi::CStr::from_ptr(mach_error_string(err)));
            return None;
        }
    }

    println!("Aquired the kernel task port! {:X}", kernel_task_port);

    let kas_slide = sys_kas_info();
    println!("Kernel slide is {:X}", kas_slide);

    let mut new_data : *const u8 = 0 as *const u8;
    let mut data_count : u64 = 0;
    match mach_vm_read(
        kernel_task_port,
        addr,
        8,
        &mut new_data,
        &mut data_count
    ) {
        KERN_SUCCESS => {},
        err => {
            println!("Error reading from kernel memory. Error code 0x{:X} ({:?})", err, std::ffi::CStr::from_ptr(mach_error_string(err)));
            return None;
        }
    }

    return None;
}

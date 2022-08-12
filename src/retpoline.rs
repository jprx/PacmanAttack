/*!
 * Generate a trampoline made of return instructions.
 */

use crate::*;

/// The opcode for a return instruction
pub const RET_INST : u32 = 0xd65f03c0;
pub const NOP_INST : u32 = 0xd503201f;

/**
 * Fill a page with `ret` instructions, and make it executable.
 *
 * # Return Value
 * Returns Error on failure, Ok on success.
 */
pub unsafe fn mk_retpoline_page(page: &mut [u8]) -> Result<(), ()> {
    if page.len() < cache::PAGE_SIZE {
        return Err(());
    }

    let retpoline_ptr = page.as_mut_ptr();

    match mach_vm_protect(
        mach_task_self(),
        retpoline_ptr,
        cache::PAGE_SIZE,
        0,
        (VM_PROT_READ | VM_PROT_WRITE)
    ) {
        KERN_SUCCESS => {},
        err => {
            println!("Error calling mach_vm_protect! Error code 0x{:X} ({:?})", err, std::ffi::CStr::from_ptr(mach_error_string(err)));
            return Err(());
        }
    }

    let page_as_u32 = core::slice::from_raw_parts_mut(retpoline_ptr as *mut u32, cache::PAGE_SIZE / core::mem::size_of::<u32>());
    page_as_u32.fill(RET_INST);

    match mach_vm_protect(
        mach_task_self(),
        retpoline_ptr,
        cache::PAGE_SIZE,
        0,
        (VM_PROT_READ | VM_PROT_EXECUTE)
    ) {
        KERN_SUCCESS => {},
        err => {
            println!("Error calling mach_vm_protect! Error code 0x{:X} ({:?})", err, std::ffi::CStr::from_ptr(mach_error_string(err)));
            return Err(());
        }
    }

    return Ok(());
}

/**
 * Fill a given memory range with `ret` instructions, and make it executable.
 *
 * # Return Value
 * Returns Error on failure, Ok on success.
 */
 pub unsafe fn mk_retpoline_addr(addr: u64, size: usize) -> Result<(), ()> {
    let retpoline_ptr = addr as *mut u8;

    match mach_vm_protect(
        mach_task_self(),
        retpoline_ptr,
        size,
        0,
        (VM_PROT_READ | VM_PROT_WRITE)
    ) {
        KERN_SUCCESS => {},
        err => {
            println!("Error calling mach_vm_protect! Error code 0x{:X} ({:?})", err, std::ffi::CStr::from_ptr(mach_error_string(err)));
            return Err(());
        }
    }

    let page_as_u32 = core::slice::from_raw_parts_mut(retpoline_ptr as *mut u32, size / core::mem::size_of::<u32>());
    page_as_u32.fill(RET_INST);

    match mach_vm_protect(
        mach_task_self(),
        retpoline_ptr,
        size,
        0,
        (VM_PROT_READ | VM_PROT_EXECUTE)
    ) {
        KERN_SUCCESS => {},
        err => {
            println!("Error calling mach_vm_protect! Error code 0x{:X} ({:?})", err, std::ffi::CStr::from_ptr(mach_error_string(err)));
            return Err(());
        }
    }

    return Ok(());
}

/*!
 * Shared information between the user attack and the PacmanKit kext.
 */
use std::ffi::{CStr, CString};
use crate::iokit::*;
use crate::mach::*;
use crate::timer;

/// Offset in bytes within a PacmanUser IOUserClient to the helper field
pub const PACMANKIT_TO_HELPER : u64 = 0xE0;

/**
 * The operations supported by the PacmanKit kext.
 *
 * Each of these is an ::externalMethod selector.
 */
#[repr(u32)]
pub enum PacmanKitOp {
    KernelBase        = 0x00,
    Read              = 0x01,
    Write             = 0x02,
    KernelVirt2Phys   = 0x03,
    UserVirt2Phys     = 0x04,
    IOUserClientLeak  = 0x05,
    GimmeMemory       = 0x06,
    FreeMemory        = 0x07,
    TellMeRegs        = 0x08,
    ReadForTiming     = 0x09,
    ExecForTiming     = 0x0A,
    LeakMethod        = 0x0B,
    ReadForSpectre    = 0x0C,
    ExecForSpectre    = 0x0D,
    CallServiceRoutine= 0x0E,
    ForgeSignData     = 0x0F,
    ForgeAuthData     = 0x10,
    ForgeSignInst     = 0x11,
    ForgeAuthInst     = 0x12,
    LeakCurProc       = 0x13,
}

/**
 * An object representing a connection to the PacmanKit IOUserClient in the PacmanKit kext.
 *
 * This can be used to run all the operations provided by the PacmanKit kext.
 */
pub struct PacmanKitConnection(IOConnect, IOService);

impl PacmanKitConnection {
    /**
     * Create a new PacmanKitConnection.
     * This opens a new IOUserClient and may fail.
     *
     * # Return Value
     * Returns the `kern_return_t` error on failure, a valid PacmanKitConnection on success.
     */
    pub unsafe fn init() -> Option<Self> {
        let mut kret : KernReturn;
        let mut name : IOName = [0;128];
        let mut handle : IOConnect = 0;
        let service_name = CString::new("PacmanKit").unwrap();
        let serv = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching(service_name.as_ptr()));
        if IO_OBJECT_NULL == serv {
            println!("Couldn't find PacmanKit. Did you remember to install it?");
            return None;
        }

        IORegistryEntryGetName(serv, &mut name);
        kret = IOServiceOpen(serv, mach_task_self(), 0, &mut handle);
        if KERN_SUCCESS != kret {
            println!("Couldn't connect to IOService {:?} (error {:?}", CStr::from_ptr(&name as *const _), CStr::from_ptr(mach_error_string(kret)));
            IOObjectRelease(serv);
            return None;
        }

        return Some(Self(
            handle,
            serv
        ));
    }

    /**
     * Returns the kernel base address (pointer to the macho header of the kernelcache).
     */
    pub unsafe fn get_kernel_base(&self) -> Result<u64, KernReturn> {
        let mut kaslr_base = 0;
        let mut output_cnt = 1;
        let kret = IOConnectCallScalarMethod(
            self.0,
            PacmanKitOp::KernelBase as u32,
            core::ptr::null(),
            0,
            &mut kaslr_base,
            &mut output_cnt
        );

        if kret != KERN_SUCCESS {
            println!("Couldn't leak kernel base! (error {:?})", CStr::from_ptr(mach_error_string(kret)));
            return Err(kret);
        }

        return Ok(kaslr_base);
    }

    /**
     * Read a u64 from kernel virtual memory.
     */
    pub unsafe fn kernel_read(&self, addr: u64) -> Result<u64, KernReturn> {
        let mut output_cnt = 1;
        let mut read_out = 0;
        let kret = IOConnectCallScalarMethod(
            self.0,
            PacmanKitOp::Read as u32,
            &addr,
            1,
            &mut read_out,
            &mut output_cnt
        );

        if KERN_SUCCESS != kret {
            println!("Couldn't read from kernel memory (error {:?})", CStr::from_ptr(mach_error_string(kret)));
            return Err(kret);
        }

        return Ok(read_out);
    }

    /**
     * Write a u64 into kernel memory.
     */
    pub unsafe fn kernel_write(&self, addr: u64, val: u64) -> Result<(), KernReturn> {
        let args : [u64; 2] = [addr, val];
        let kret = IOConnectCallScalarMethod(
            self.0,
            PacmanKitOp::Write as u32,
            args.as_ptr(),
            2,
            core::ptr::null_mut(),
            core::ptr::null_mut()
        );

        if KERN_SUCCESS != kret {
            println!("Couldn't write to kernel memory (error {:?})", CStr::from_ptr(mach_error_string(kret)));
            return Err(kret);
        }

        return Ok(());
    }

    /**
     * Translate a kernel virtual address to its physical address.
     */
    pub unsafe fn kernel_virt_to_phys(&self, addr: u64) -> Result<u64, KernReturn> {
        let mut output_cnt = 1;
        let mut translate_out = 0;
        let kret = IOConnectCallScalarMethod(
            self.0,
            PacmanKitOp::KernelVirt2Phys as u32,
            &addr,
            1,
            &mut translate_out,
            &mut output_cnt
        );

        if KERN_SUCCESS != kret {
            println!("Couldn't translate kernel address (error {:?})", CStr::from_ptr(mach_error_string(kret)));
            return Err(kret);
        }

        return Ok(translate_out);
    }

    /**
     * Translate a user virtual address to its physical address.
     */
    pub unsafe fn user_virt_to_phys(&self, addr: u64) -> Result<u64, KernReturn> {
        let mut output_cnt = 1;
        let mut translate_out = 0;
        let kret = IOConnectCallScalarMethod(
            self.0,
            PacmanKitOp::UserVirt2Phys as u32,
            &addr,
            1,
            &mut translate_out,
            &mut output_cnt
        );

        if KERN_SUCCESS != kret {
            println!("Couldn't translate user address (error {:?})", CStr::from_ptr(mach_error_string(kret)));
            return Err(kret);
        }

        return Ok(translate_out);
    }

    /**
     * Returns a pointer to this IOUserClient in the kernel.
     */
    pub unsafe fn get_handle_loc(&self) -> Result<u64, KernReturn> {
        let mut handle_loc = 0;
        let mut output_cnt = 1;
        let kret = IOConnectCallScalarMethod(
            self.0,
            PacmanKitOp::IOUserClientLeak as u32,
            core::ptr::null(),
            0,
            &mut handle_loc,
            &mut output_cnt
        );

        if KERN_SUCCESS != kret {
            println!("Couldn't get IOConnect virtual address (error {:?})", CStr::from_ptr(mach_error_string(kret)));
            return Err(kret);
        }

        return Ok(handle_loc);
    }

    /**
     * Returns a pointer to a kernel memory region mmap'ed by IOMallocAligned to a page size.
     */
    pub unsafe fn kernel_mmap(&self) -> Result<u64, KernReturn> {
        let mut mmap_ptr = 0;
        let mut output_cnt = 1;
        let kret = IOConnectCallScalarMethod(
            self.0,
            PacmanKitOp::GimmeMemory as u32,
            core::ptr::null(),
            0,
            &mut mmap_ptr,
            &mut output_cnt
        );

        if KERN_SUCCESS != kret {
            println!("Couldn't get kernel mmap (error {:?})", CStr::from_ptr(mach_error_string(kret)));
            return Err(kret);
        }

        return Ok(mmap_ptr);
    }

    /**
     * Frees memory allocated by kernel_mmap.
     */
     pub unsafe fn kernel_free(&self) -> Result<(), KernReturn> {
        let kret = IOConnectCallScalarMethod(
            self.0,
            PacmanKitOp::FreeMemory as u32,
            core::ptr::null(),
            0,
            core::ptr::null_mut(),
            core::ptr::null_mut()
        );

        if KERN_SUCCESS != kret {
            println!("Couldn't get kernel mmap (error {:?})", CStr::from_ptr(mach_error_string(kret)));
            return Err(kret);
        }

        return Ok(());
    }

    pub unsafe fn list_timer_regs(&self) {
        let mut rval : [u64; 2] = [0, 0];
        let mut num_args : u32 = 2;
        let kret = IOConnectCallScalarMethod(
            self.0,
            PacmanKitOp::TellMeRegs as u32,
            core::ptr::null(),
            0,
            rval.as_mut_ptr(),
            &mut num_args as *mut _,
        );

        if KERN_SUCCESS != kret {
            println!("Couldn't read timer MSRs (error {:?})", CStr::from_ptr(mach_error_string(kret)));
            return;
        }

        println!("PMCR0 is 0x{:X}", rval[0]);
        println!("CNTKCTL_EL1 is 0x{:X}", rval[1]);

        return;
    }

    /**
     * Read a u64 from kernel virtual memory without any IOMemoryDescriptor calls.
     * This *CAN* panic the kernel!
     *
     * # Arguments
     * * `addr`: A kernel address to load
     * * `do_it`: Should the load actually run?
     *
     * # Return Value
     * Returns the number of cycles taken if `do_it` was true. Else, returns an undefined value.
     */
     pub unsafe fn kernel_read_for_timing(&self, addr: u64, do_it: bool) -> Result<u64, KernReturn> {
        let mut output_cnt = 1;
        let mut read_out = 0;
        let args : [u64; 2] = [addr, do_it as u64];
        let kret = IOConnectCallScalarMethod(
            self.0,
            PacmanKitOp::ReadForTiming as u32,
            args.as_ptr(),
            2,
            &mut read_out,
            &mut output_cnt
        );

        if KERN_SUCCESS != kret {
            println!("Couldn't read from kernel memory (error {:?})", CStr::from_ptr(mach_error_string(kret)));
            return Err(kret);
        }

        return Ok(read_out - timer::TIMER_OVERHEAD_PCORE);
    }

    /**
     * Exec a u64 from kernel virtual memory without any IOMemoryDescriptor calls.
     * This *CAN* panic the kernel!
     *
     * # Arguments
     * * `addr`: A kernel address to exec
     * * `do_it`: Should the call actually run?
     *
     * # Return Value
     * Returns the number of cycles taken if `do_it` was true. Else, returns an undefined value.
     */
     pub unsafe fn kernel_exec_for_timing(&self, addr: u64, do_it: bool) -> Result<u64, KernReturn> {
        let mut output_cnt = 1;
        let mut read_out = 0;
        let args : [u64; 2] = [addr, do_it as u64];
        let kret = IOConnectCallScalarMethod(
            self.0,
            PacmanKitOp::ExecForTiming as u32,
            args.as_ptr(),
            2,
            &mut read_out,
            &mut output_cnt
        );

        if KERN_SUCCESS != kret {
            println!("Couldn't exec from kernel memory (error {:?})", CStr::from_ptr(mach_error_string(kret)));
            return Err(kret);
        }

        return Ok(read_out - timer::TIMER_OVERHEAD_PCORE);
    }

    /**
     * Returns a pointer to a kernel method that just runs `ret`.
     */
     pub unsafe fn leak_retpoline(&self) -> Result<u64, KernReturn> {
        let mut method_leak_ptr : [u64; 3] = [0; 3];
        let mut output_cnt = 3;
        let kret = IOConnectCallScalarMethod(
            self.0,
            PacmanKitOp::LeakMethod as u32,
            core::ptr::null(),
            0,
            method_leak_ptr.as_mut_ptr(),
            &mut output_cnt
        );

        if KERN_SUCCESS != kret {
            println!("Couldn't get reveal address of a kernel method (error {:?})", CStr::from_ptr(mach_error_string(kret)));
            return Err(kret);
        }

        return Ok(method_leak_ptr[0]);
    }

    /**
     * Returns a pointer to the `LIMIT` variable in the PacmanKit kext.
     */
     pub unsafe fn leak_limit_location(&self) -> Result<u64, KernReturn> {
        let mut method_leak_ptr : [u64; 3] = [0; 3];
        let mut output_cnt = 3;
        let kret = IOConnectCallScalarMethod(
            self.0,
            PacmanKitOp::LeakMethod as u32,
            core::ptr::null(),
            0,
            method_leak_ptr.as_mut_ptr(),
            &mut output_cnt
        );

        if KERN_SUCCESS != kret {
            println!("Couldn't get reveal address of the kext limit (error {:?})", CStr::from_ptr(mach_error_string(kret)));
            return Err(kret);
        }

        return Ok(method_leak_ptr[1]);
    }

    /**
     * Returns a pointer to the win() method in the PacmanKit kext.
     */
     pub unsafe fn leak_win(&self) -> Result<u64, KernReturn> {
        panic!("This has been deprecated- use leak_retpoline to reveal a region full of `ret`s that can be used");
        // let mut method_leak_ptr : [u64; 3] = [0; 3];
        // let mut output_cnt = 3;
        // let kret = IOConnectCallScalarMethod(
        //     self.0,
        //     PacmanKitOp::LeakMethod as u32,
        //     core::ptr::null(),
        //     0,
        //     method_leak_ptr.as_mut_ptr(),
        //     &mut output_cnt
        // );

        // if KERN_SUCCESS != kret {
        //     println!("Couldn't get reveal address of the kext limit (error {:?})", CStr::from_ptr(mach_error_string(kret)));
        //     return Err(kret);
        // }

        // return Ok(method_leak_ptr[2]);
    }

    /**
     * Read a u64 from kernel virtual memory without any IOMemoryDescriptor calls.
     * This *CAN* panic the kernel!
     *
     * This is very similar to kernel_read_for_timing except it features no synchronization
     * barriers (so speculation can cause the load to happen) and does not report any latencies.
     *
     * # Arguments
     * * `addr`: A kernel address to load
     * * `idx`: Index passed in to the 'bounds check'
     *
     * # Return Value
     * Returns Nothing.
     */
     pub unsafe fn kernel_read_for_spectre(&self, addr: u64, idx: u64) -> Result<(), KernReturn> {
        let args : [u64; 2] = [addr, idx];
        let kret = IOConnectCallScalarMethod(
            self.0,
            PacmanKitOp::ReadForSpectre as u32,
            args.as_ptr(),
            2,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );

        if KERN_SUCCESS != kret {
            println!("Couldn't read from kernel memory (error {:?})", CStr::from_ptr(mach_error_string(kret)));
            return Err(kret);
        }

        return Ok(());
    }

    /**
     * Exec a u64 from kernel virtual memory without any IOMemoryDescriptor calls.
     * This *CAN* panic the kernel!
     *
     * This is very similar to kernel_exec_for_timing except it features no synchronization
     * barriers (so speculation can cause the load to happen) and does not report any latencies.
     *
     * # Arguments
     * * `addr`: A kernel address to exec
     * * `idx`: Index passed in to the 'bounds check'
     *
     * # Return Value
     * Returns Nothing.
     */
     pub unsafe fn kernel_exec_for_spectre(&self, addr: u64, idx: u64) -> Result<(), KernReturn> {
        let args : [u64; 2] = [addr, idx];
        let kret = IOConnectCallScalarMethod(
            self.0,
            PacmanKitOp::ExecForSpectre as u32,
            args.as_ptr(),
            2,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );

        if KERN_SUCCESS != kret {
            println!("Couldn't exec from kernel memory (error {:?})", CStr::from_ptr(mach_error_string(kret)));
            return Err(kret);
        }

        return Ok(());
    }

    pub unsafe fn call_service_routine(&self, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64, arg6: u64) -> Result<u64, KernReturn> {
        let args : [u64; 6] = [arg1, arg2, arg3, arg4, arg5, arg6];
        let mut output_cnt = 1;
        let mut output_val = 0u64;

        let kret = IOConnectCallScalarMethod(
            self.0,
            PacmanKitOp::CallServiceRoutine as u32,
            args.as_ptr(),
            6,
            &mut output_val,
            &mut output_cnt
        );

        // Ignore errors...
        if KERN_SUCCESS != kret {
            // println!("Couldn't call service routine {}!", arg1);
            // return Err(kret);
        }

        return Ok(output_val);
    }

    /// Returns the correct PACDA signature from the kernel. This can ONLY be used for testing!
    /// The real attack will need to use brute force to find this. We only use this method to learn
    /// the ground truth for generating plots and tuning the algorithm.
    pub unsafe fn forge_sign_data(&self, addr: u64, salt: u64) -> Result<u64, KernReturn> {
        let args : [u64; 2] = [addr, salt];
        let mut output_cnt = 1;
        let mut output_val = 1;

        let kret = IOConnectCallScalarMethod(
            self.0,
            PacmanKitOp::ForgeSignData as u32,
            args.as_ptr(),
            2,
            &mut output_val,
            &mut output_cnt
        );

        if KERN_SUCCESS != kret {
            println!("Couldn't forge PACDA for addr 0x{:X} with salt 0x{:X}", addr, salt);
            return Err(kret);
        }

        return Ok(output_val);
    }

    /// Returns the correct AUTDA signature from the kernel. This can ONLY be used for testing!
    /// The real attack cannot do this.
    pub unsafe fn forge_auth_data(&self, addr: u64, salt: u64) -> Result<u64, KernReturn> {
        let args : [u64; 2] = [addr, salt];
        let mut output_cnt = 1;
        let mut output_val = 1;

        let kret = IOConnectCallScalarMethod(
            self.0,
            PacmanKitOp::ForgeAuthData as u32,
            args.as_ptr(),
            2,
            &mut output_val,
            &mut output_cnt
        );

        if KERN_SUCCESS != kret {
            println!("Couldn't forge AUTDA for addr 0x{:X} with salt 0x{:X}", addr, salt);
            return Err(kret);
        }

        return Ok(output_val);
    }

    /// Returns the correct PACIA signature from the kernel. This can ONLY be used for testing!
    /// The real attack will need to use brute force to find this. We only use this method to learn
    /// the ground truth for generating plots and tuning the algorithm.
    pub unsafe fn forge_sign_inst(&self, addr: u64, salt: u64) -> Result<u64, KernReturn> {
        let args : [u64; 2] = [addr, salt];
        let mut output_cnt = 1;
        let mut output_val = 1;

        let kret = IOConnectCallScalarMethod(
            self.0,
            PacmanKitOp::ForgeSignInst as u32,
            args.as_ptr(),
            2,
            &mut output_val,
            &mut output_cnt
        );

        if KERN_SUCCESS != kret {
            println!("Couldn't forge PACIA for addr 0x{:X} with salt 0x{:X}", addr, salt);
            return Err(kret);
        }

        return Ok(output_val);
    }

    /// Returns the correct AUTIA signature from the kernel. This can ONLY be used for testing!
    /// The real attack cannot do this.
    pub unsafe fn forge_auth_inst(&self, addr: u64, salt: u64) -> Result<u64, KernReturn> {
        let args : [u64; 2] = [addr, salt];
        let mut output_cnt = 1;
        let mut output_val = 1;

        let kret = IOConnectCallScalarMethod(
            self.0,
            PacmanKitOp::ForgeAuthInst as u32,
            args.as_ptr(),
            2,
            &mut output_val,
            &mut output_cnt
        );

        if KERN_SUCCESS != kret {
            println!("Couldn't forge AUTIA for addr 0x{:X} with salt 0x{:X}", addr, salt);
            return Err(kret);
        }

        return Ok(output_val);
    }

    /// Leak the current proc pointer
    pub unsafe fn current_proc(&self) -> Result<u64, KernReturn> {
        let mut leak_ptr : [u64; 1] = [0; 1];
        let mut output_cnt = 1;
        let kret = IOConnectCallScalarMethod(
            self.0,
            PacmanKitOp::LeakCurProc as u32,
            core::ptr::null(),
            0,
            leak_ptr.as_mut_ptr(),
            &mut output_cnt
        );

        if KERN_SUCCESS != kret {
            println!("Couldn't call current_proc() (error {:?})", CStr::from_ptr(mach_error_string(kret)));
            return Err(kret);
        }

        return Ok(leak_ptr[0]);
    }
}

impl Drop for PacmanKitConnection {
    /**
     * Clean up our IOKit connection.
     */
    fn drop(&mut self) {
        println!("Dropping a PacmanKitConnection ({:X}, {:X})", self.0, self.1);
        unsafe {
            IOServiceClose(self.0);
            IOObjectRelease(self.1);
        }
    }
}

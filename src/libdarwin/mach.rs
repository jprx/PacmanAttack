/*!
 * Bindings to various libsystem mach endpoints.
 */

pub const VM_PROT_NONE : u64 = 0x00;
pub const VM_PROT_READ : u64 = 0x01;
pub const VM_PROT_WRITE : u64 = 0x02;
pub const VM_PROT_EXECUTE : u64 = 0x04;

/// (for vm_allocate): Place memory allocation anywhere
pub const VM_FLAGS_ANYWHERE : u64 = 0x0001;

/// (for vm_allocate): Use huge pages
pub const VM_FLAGS_SUPERPAGE_MASK : u64 = 0x70000;

pub const KERN_SUCCESS : KernReturn = 0;

pub type MachPort = u32;
pub type KernReturn = i32;

#[link(name = "system")]
extern "C" {
    /**
     * Binding to the mach_absolute_time method from libsystem.
     */
    pub fn mach_absolute_time() -> u64;
}

/**
 * Returns a counter that represents the current time.
 */
pub fn gettime() -> u64 {
    unsafe {
        return mach_absolute_time();
    }
}

#[link(name = "system")]
extern "C" {
    #[doc(hidden)]
    static mach_task_self_ : MachPort;

    /**
     * Allocate a chunk of memory.
     *
     * # Arguments
     * * `target`: The port to allocate memory on.
     * * `addr`: A mutable pointer that will be updated to contain the address of the new memory.
     * * `size`: How many bytes to allocate?
     * * `flags`: Various flags to control allocation.
     *
     * # Return Value
     * Returns a kernel error return type (`kern_return_t`). If this is not `KERN_SUCCESS`,
     * then some sort of error occurred. The error can be viewed with `mach_error_string`.
     */
    pub fn mach_vm_allocate(target: MachPort, addr: *mut *mut u8, size: usize, flags: u64) -> KernReturn;

    /**
     * Change protections on a chunk of memory.
     *
     * # Arguments
     * * `target`: The port that owns the address.
     * * `addr`: Which address to update?
     * * `size`: How many bytes to update?
     * * `set_max`
     * * `new_prot`: New bit vector of protections to add.
     *
     * # Return Value
     * Returns a kernel error return type (`kern_return_t`). If this is not `KERN_SUCCESS`,
     * then some sort of error occurred. The error can be viewed with `mach_error_string`.
     */
    pub fn mach_vm_protect(target: MachPort, addr: *const u8, size: usize, set_max: u32, new_prot: u64) -> KernReturn;

    /**
     * Read virtual memory from a mach port.
     *
     * # Arguments
     * * `target`: The port to read from.
     * * `addr`: Virtual address in the port to read.
     * * `size`: How many bytes to read?
     * * `data`: (OUT) This will be updated to point to the new buffer.
     * * `dataCount`: (OUT) This will be updated with the number of bytes read.
     *
     * # Return Value
     * Returns a kernel error return type (`kern_return_t`). If this is not `KERN_SUCCESS`,
     * then some sort of error occurred. The error can be viewed with `mach_error_string`.
     */
    pub fn mach_vm_read(target: MachPort, addr: usize, size: usize, data: *mut *const u8, dataCount: *mut u64) -> KernReturn;

    /**
     * Aquire the task port for a given process by PID.
     * If PID is 0, this gets us the kernel task port.
     *
     * # Arguments
     * * `port`: The port from which the new port should be aquired (usually just mach_task_self()).
     * * `pid`: Process ID to grab.
     * * `newTask`: Points to a mach port (aka u64) that will be updated with the new task port.
     */
    pub fn task_for_pid(port: MachPort, pid: u64, newTask: *mut MachPort) -> KernReturn;

    /**
     * Return the mach error for a given kern_return_t as a C string.
     *
     * # Arguments
     * * `err`: The error code returned from a mach call.
     *
     * # Return Value
     * Returns a pointer to a C string containing the error string.
     */
    pub fn mach_error_string(err: KernReturn) -> *const std::os::raw::c_char;
}

/**
 * Returns the current task port for this process.
 *
 * # Return Value
 * Returns the task port (for use with other mach methods).
 */
pub unsafe fn mach_task_self() -> MachPort {
    return core::ptr::read_volatile(&mach_task_self_);
}

/*!
 * FFI Bindings to the IOKit.framework library.
 */
use std::ffi::c_void;
use std::os::raw::c_char;
use crate::mach;
use mach::{KernReturn, MachPort};

pub type IOService = MachPort;
pub type IOName = [c_char;128];
pub type IOConnect = MachPort;

pub const IO_OBJECT_NULL : IOService = 0;

#[link(name = "IOKit", kind="framework")]
extern "C" {
    pub static kIOMainPortDefault : MachPort;
    pub fn IOServiceGetMatchingService(mainPort : MachPort, cfdictref : *const c_void) -> IOService;
    pub fn IOServiceMatching(name: *const i8) -> *const c_void;
    pub fn IORegistryEntryGetName(entry: IOService, name: *mut IOName) -> KernReturn;
    pub fn IOServiceOpen(service: IOService, owningTask: MachPort, r#type: u32, connect: *mut IOConnect) -> KernReturn;
    pub fn IOConnectCallScalarMethod(
        connection: IOConnect,
        selector: u32,
        input: *const u64,
        inputCnt: u32,
        output: *mut u64,
        outputCnt: *mut u32
    ) -> KernReturn;
    pub fn IOServiceClose(connect: IOConnect) -> KernReturn;
    pub fn IOObjectRelease(connect: IOConnect) -> KernReturn;
}

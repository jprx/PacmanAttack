/*!
 * Implementations of the various attacks.
 */

// Evict+Reload implementation for creating latency graphs
pub mod evict_reload;

// Prime+Probe testbed for determining effective prime+probe parameters
pub mod prime_probe;

// Spectre testbed for testing speculative execution in the kernel
pub mod spectre;

// The actual PACMAN attack code itself
pub mod pacman;

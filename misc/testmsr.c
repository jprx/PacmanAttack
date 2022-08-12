// objdump -d testmsr
// Use the hex values of each MSR instruction in Ghidra to find anything in the kernelcache
// that writes to these particular MSRs. Then you can trace those functions via the development
// kernel and XNU sources (assuming no kexts write to the MSR).
int main () {
	// PMC0:
	asm volatile("msr S3_2_c15_c0_0, x0");

	// PMCR0:
	asm volatile("msr S3_1_c15_c0_0, x0");

	// PMCR1:
	asm volatile("msr S3_1_c15_c1_0, x1");

	// READ PMCR1:
	asm volatile("mrs x2, S3_1_c15_c1_0");

	// Patch for CNTKCTL_EL1
	asm volatile("orr x8,x8,#0x300");

	// Read CNTKCTL_EL1
	asm volatile("msr CNTKCTL_EL1, x8");

	asm volatile("nop");
	asm volatile("orr x8,x8,#0xf");

	asm volatile("movk w8, #0x4700, lsl #16");

	asm volatile("autdza x0");
	asm volatile("autda x0, x1");
	asm volatile("autia x0, x1");
	asm volatile("blr x0");
	asm volatile("autiza x0");
	asm volatile("nop");
	asm volatile("autib x0, x1");
	asm volatile("blraa x0, x1");
}
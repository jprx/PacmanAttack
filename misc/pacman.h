#ifndef PACMAN_H
#define PACMAN_H

#include <stdint.h>
#include <stdbool.h>

// Pacman header v2 has the patches for the PAC and AUT macros
#define PACMAN_HEADER_VERSION ((2))

#define L1_SIZE ((0x20000))
#define L2_SIZE ((0xC00000))

// The bits that make up a PAC
#define PAC_BITMASK ((0xFFFF800000000000ULL))

// The important registers for PMC
#define SREG_PMCR0  "S3_1_c15_c0_0"
#define SREG_PMCR1  "S3_1_c15_c1_0"
#define SREG_PMC0 "S3_2_c15_c0_0"
#define SREG_PMC1 "S3_2_c15_c1_0"

/*
 * SREG_WRITE
 * Write into an MSR using an instruction barrier afterwords
 * MSR[SR] <- V
 */
#define SREG_WRITE(SR, V) \
	__asm__ volatile("msr " SR ", %0 \r\n isb \r\n" : : "r"((uint64_t)V))

/*
 * SREG_READ
 * Read from an MSR without any instruction barriers
 * Returns MSR[SR]
 */
#define SREG_READ(SR)                                       \
({                                                          \
	uint64_t VAL = 0;                                       \
	__asm__ volatile("mrs %0, " SR " \r\n" : "=r"(VAL));    \
	VAL;                                                    \
})

/*
 * pac_sign
 * Performs PACIA (sign instruction pointer with A key) on addr using
 * salt given by salt.
 *
 * Returns the signed pointer
 */
__attribute__((always_inline)) static inline uint64_t pac_sign(uint64_t addr, uint64_t salt) {
	uint64_t result = addr;
	asm volatile(
         "pacia %[result], %[salt] \n\r" \
         : [result]"+r"(result)
         : [salt]"r"(salt)
         :
	);
	return result;
}

#define PAC_SIGN(ADDR, SALT) 				\
({											\
	uint64_t PAC_VAL = ADDR;				\
	asm volatile("pacia %[result], %[salt] \n\r" : [result]"+r"(PAC_VAL) : [salt]"r"((uint64_t)SALT) : ); \
	PAC_VAL; 								\
})

/*
 * pac_auth
 * Performs AUTIA (authenticate instruction pointer with A key) on addr using
 * salt given by salt.
 *
 * Returns the signed pointer
 */
__attribute__((always_inline)) static inline uint64_t pac_auth(uint64_t addr, uint64_t salt) {
	uint64_t result = addr;
	asm volatile(
		"autia %[result], %[salt] \n\r"
		: [result]"+r"(result)
		: [salt]"r"(salt)
		:
	);
	return result;
}

#define PAC_AUTH(ADDR, SALT) 				\
({											\
	uint64_t PAC_VAL = ADDR;				\
	asm volatile("autia %[result], %[salt] \n\r" : [result]"+r"(PAC_VAL) : [salt]"r"((uint64_t)SALT) : );       \
	PAC_VAL; 								\
})

/*
 * get_current_core
 * Returns the ID of the core that we are currently executing code on.
 */
static uint64_t get_current_core(void) {
	return SREG_READ("TPIDRRO_EL0") & 7;
}

#endif // PACMAN_H

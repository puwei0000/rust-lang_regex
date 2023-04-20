// This set of tests is different from regression_fuzz in that the tests start
// from the fuzzer data directly. The test essentially duplicates the fuzz
// target. I wonder if there's a better way to set this up... Hmmm. I bet
// `cargo fuzz` has something where it can run a target against crash files and
// verify that they pass.

// This case found by the fuzzer causes the meta engine to use the "reverse
// inner" literal strategy. That in turn uses a specialized search routine
// for the lazy DFA in order to avoid worst case quadratic behavior. That
// specialized search routine had a bug where it assumed that start state
// specialization was disabled. But this is indeed not the case, since it
// reuses the "general" lazy DFA for the full regex created as part of the core
// strategy, which might very well have start states specialized due to the
// existence of a prefilter.
//
// This is a somewhat weird case because if the core engine has a prefilter,
// then it's usually the case that the "reverse inner" optimization won't be
// pursued in that case. But there are some heuristics that try to detect
// whether a prefilter is "fast" or not. If it's not, then the meta engine will
// attempt the reverse inner optimization. And indeed, that's what happens
// here. So the reverse inner optimization ends up with a lazy DFA that has
// start states specialized. Ideally this wouldn't happen because specializing
// start states without a prefilter inside the DFA can be disastrous for
// performance by causing the DFA to ping-pong in and out of the special state
// handling. In this case, it's probably not a huge deal because the lazy
// DFA is only used for part of the matching where as the work horse is the
// prefilter found by the reverse inner optimization.
//
// We could maybe fix this by refactoring the meta engine to be a little more
// careful. For example, by attempting the optimizations before building the
// core engine. But this is perhaps a little tricky.
#[test]
fn meta_stopat_specialize_start_states() {
    let data = include_bytes!(
        "testdata/crash-8760b19b25d74e3603d4c643e9c7404fdd3631f9",
    );
    let _ = run(data);
}

// Same bug as meta_stopat_specialize_start_states, but minimized by the
// fuzzer.
#[test]
fn meta_stopat_specialize_start_states_min() {
    let data = include_bytes!(
        "testdata/minimized-from-8760b19b25d74e3603d4c643e9c7404fdd3631f9",
    );
    let _ = run(data);
}

// This input generated a pattern with a fail state (e.g., \P{any}, [^\s\S]
// or [a&&b]). But the fail state was in a branch, where a subsequent branch
// should have led to an overall match, but handling of the fail state
// prevented it from doing so. A hand-minimized version of this is '[^\s\S]A|B'
// on the haystack 'B'. That should yield a match of 'B'.
//
// The underlying cause was an issue in how DFA determinization handled fail
// states. The bug didn't impact the PikeVM or the bounded backtracker.
#[test]
fn fail_branch_prevents_match() {
    let data = include_bytes!(
        "testdata/crash-cd33b13df59ea9d74503986f9d32a270dd43cc04",
    );
    let _ = run(data);
}

// This is the fuzz target function. We duplicate it here since this is the
// thing we use to interpret the data. It is ultimately what we want to
// succeed.
fn run(data: &[u8]) -> Option<()> {
    if data.len() < 2 {
        return None;
    }
    let mut split_at = usize::from(data[0]);
    let data = std::str::from_utf8(&data[1..]).ok()?;
    // Split data into a regex and haystack to search.
    let len = usize::try_from(data.chars().count()).ok()?;
    split_at = std::cmp::max(split_at, 1) % len;
    let char_index = data.char_indices().nth(split_at)?.0;
    let (pattern, input) = data.split_at(char_index);
    let re = regex::Regex::new(pattern).ok()?;
    re.is_match(input);
    Some(())
}

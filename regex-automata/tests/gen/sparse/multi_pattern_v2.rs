// DO NOT EDIT THIS FILE. IT WAS AUTOMATICALLY GENERATED BY:
//
//     regex-cli generate serialize sparse regex MULTI_PATTERN_V2 tests/gen/sparse/ --rustfmt --safe --starts-for-each-pattern --specialize-start-states --start-kind both --unicode-word-boundary --minimize \b[a-zA-Z]+\b (?m)^\S+$ (?Rm)^\S+$
//
// regex-cli 0.0.1 is available on crates.io.

use regex_automata::{
    dfa::{regex::Regex, sparse::DFA},
    util::lazy::Lazy,
};

pub static MULTI_PATTERN_V2: Lazy<Regex<DFA<&'static [u8]>>> =
    Lazy::new(|| {
        let dfafwd = {
            #[cfg(target_endian = "big")]
            static BYTES: &'static [u8] =
                include_bytes!("multi_pattern_v2_fwd.bigendian.dfa");
            #[cfg(target_endian = "little")]
            static BYTES: &'static [u8] =
                include_bytes!("multi_pattern_v2_fwd.littleendian.dfa");
            DFA::from_bytes(BYTES)
                .expect("serialized forward DFA should be valid")
                .0
        };
        let dfarev = {
            #[cfg(target_endian = "big")]
            static BYTES: &'static [u8] =
                include_bytes!("multi_pattern_v2_rev.bigendian.dfa");
            #[cfg(target_endian = "little")]
            static BYTES: &'static [u8] =
                include_bytes!("multi_pattern_v2_rev.littleendian.dfa");
            DFA::from_bytes(BYTES)
                .expect("serialized reverse DFA should be valid")
                .0
        };
        Regex::builder().build_from_dfas(dfafwd, dfarev)
    });
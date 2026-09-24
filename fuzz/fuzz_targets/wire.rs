#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| leelo_fuzz::wire(data));

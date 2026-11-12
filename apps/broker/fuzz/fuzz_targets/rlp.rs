#![no_main]
//! RLP length-prefix encoding must follow the specification.

use libfuzzer_sys::fuzz_target;
use tessera_broker::eth::Rlp;

fuzz_target!(|data: &[u8]| {
    let encoded = Rlp::Bytes(data).encode();

    if data.len() == 1 && data[0] < 0x80 {
        // single small byte is itself
        assert_eq!(encoded, data.to_vec());
    } else if data.len() < 56 {
        assert_eq!(encoded[0] as usize, 0x80 + data.len());
    } else {
        assert!(encoded[0] >= 0xb8);
    }
});

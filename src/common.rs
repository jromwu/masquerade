use quiche::h3::NameValue;


pub const MAX_DATAGRAM_SIZE: usize = 1350;

pub fn hdrs_to_strings(hdrs: &[quiche::h3::Header]) -> Vec<(String, String)> {
    hdrs.iter()
        .map(|h| {
            let name = String::from_utf8_lossy(h.name()).to_string();
            let value = String::from_utf8_lossy(h.value()).to_string();

            (name, value)
        })
        .collect()
}

pub fn hex_dump(buf: &[u8]) -> String {
    let vec: Vec<String> = buf.iter().map(|b| format!("{:02x}", b)).collect();

    vec.join("")
}

pub fn would_block(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::WouldBlock
}

pub fn interrupted(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::Interrupted
}

/*
 * Decode variable-length integer in QUIC and related protocols
 * 
 * ref: https://www.rfc-editor.org/rfc/rfc9000#sample-varint
 */
pub fn decode_var_int(data: &[u8]) -> (u64, &[u8]) {
    // The length of variable-length integers is encoded in the
    // first two bits of the first byte.
    let mut v: u64 = data[0].into();
    let prefix = v >> 6;
    let length = 1 << prefix;

    // Once the length is known, remove these bits and read any
    // remaining bytes.
    v = v & 0x3f;
    for i in 1..length-1 {
        v = (v << 8) + Into::<u64>::into(data[i]);
    }

    (v, &data[length..])
}

pub const MAX_VAR_INT: u64 = u64::pow(2, 62) - 1;
const MAX_INT_LEN_4: u64 = u64::pow(2, 30) - 1;
const MAX_INT_LEN_2: u64 = u64::pow(2, 14) - 1;
const MAX_INT_LEN_1: u64 = u64::pow(2, 6) - 1;

pub fn encode_var_int(v: u64) -> Vec<u8> {
    assert!(v <= MAX_VAR_INT);
    let length = if v > MAX_INT_LEN_4 {
        8
    } else if v > MAX_INT_LEN_2 {
        4
    } else if v > MAX_INT_LEN_1 {
        2
    } else {
        1
    };

    let mut encoded = v.to_be_bytes().to_vec();
    let prefix: u8 = length << 6;
    encoded[0] = encoded[0] | prefix;
    encoded
}

pub fn wrap_udp_connect_payload(context_id: u64, payload: &[u8]) -> Vec<u8> {
    let context_id = encode_var_int(context_id);
    let context_id = encode_var_int(0);
    let mut data = Vec::with_capacity(context_id.len() + payload.len());
    data[..context_id.len()].copy_from_slice(&context_id);
    data[context_id.len()..].copy_from_slice(payload);
    data
}


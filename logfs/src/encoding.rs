//! Bincode 1-compatible serialization on bincode 2.

pub(crate) fn serialize<T: serde::Serialize + ?Sized>(
    value: &T,
) -> Result<Vec<u8>, bincode::error::EncodeError> {
    bincode::serde::encode_to_vec(value, bincode::config::legacy())
}

pub(crate) fn serialized_size<T: serde::Serialize + ?Sized>(
    value: &T,
) -> Result<u64, bincode::error::EncodeError> {
    let written = bincode::serde::encode_into_std_write(
        value,
        &mut std::io::sink(),
        bincode::config::legacy(),
    )?;
    Ok(written as u64)
}

pub(crate) fn deserialize<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
) -> Result<T, bincode::error::DecodeError> {
    decode_with_config(bytes, bincode::config::legacy())
}

pub(crate) fn deserialize_bounded<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    limit: usize,
) -> Result<T, bincode::error::DecodeError> {
    if bytes.len() > limit {
        return Err(bincode::error::DecodeError::LimitExceeded);
    }

    macro_rules! decode_with_limit {
        ($limit:literal) => {
            decode_with_config(bytes, bincode::config::legacy().with_limit::<$limit>())
        };
    }

    match limit {
        0..=1_024 => decode_with_limit!(1_024),
        1_025..=2_048 => decode_with_limit!(2_048),
        2_049..=4_096 => decode_with_limit!(4_096),
        4_097..=8_192 => decode_with_limit!(8_192),
        8_193..=16_384 => decode_with_limit!(16_384),
        16_385..=32_768 => decode_with_limit!(32_768),
        32_769..=65_536 => decode_with_limit!(65_536),
        65_537..=131_072 => decode_with_limit!(131_072),
        131_073..=262_144 => decode_with_limit!(262_144),
        262_145..=524_288 => decode_with_limit!(524_288),
        524_289..=1_048_576 => decode_with_limit!(1_048_576),
        1_048_577..=2_097_152 => decode_with_limit!(2_097_152),
        2_097_153..=4_194_304 => decode_with_limit!(4_194_304),
        4_194_305..=8_388_608 => decode_with_limit!(8_388_608),
        8_388_609..=16_777_216 => decode_with_limit!(16_777_216),
        16_777_217..=33_554_432 => decode_with_limit!(33_554_432),
        33_554_433..=67_108_864 => decode_with_limit!(67_108_864),
        67_108_865..=134_217_728 => decode_with_limit!(134_217_728),
        134_217_729..=268_435_456 => decode_with_limit!(268_435_456),
        268_435_457..=536_870_912 => decode_with_limit!(536_870_912),
        _ => Err(bincode::error::DecodeError::LimitExceeded),
    }
}

fn decode_with_config<T, C>(bytes: &[u8], config: C) -> Result<T, bincode::error::DecodeError>
where
    T: serde::de::DeserializeOwned,
    C: bincode::config::Config,
{
    let (value, _) = bincode::serde::decode_from_slice(bytes, config)?;
    Ok(value)
}

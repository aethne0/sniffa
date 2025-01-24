pub fn octets_to_ascii(octets: &[u8]) -> String {
    let x = octets
        .iter()
        .map(|&octet| {
            if octet >= 32 && octet <= 126 {
                char::from(octet)
            } else {
                '.'
            }
        })
        .collect::<Vec<_>>();

    x.iter().collect()
}

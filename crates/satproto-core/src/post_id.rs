use rand::Rng;

/// Generate a post ID: {ISO8601-compact-UTC}-{4-hex-random}
/// e.g. "20260309T141500Z-a1b2"
pub fn generate_post_id(now: &str) -> String {
    let mut rng = rand::thread_rng();
    let suffix: u16 = rng.gen();
    format!("{}-{:04x}", now, suffix)
}

/// Format a timestamp into compact ISO 8601 UTC for use in post IDs.
/// Input: "2026-03-09T14:15:00Z" -> Output: "20260309T141500Z"
pub fn compact_timestamp(iso: &str) -> String {
    iso.replace('-', "").replace(':', "")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compact_timestamp() {
        assert_eq!(
            compact_timestamp("2026-03-09T14:15:00Z"),
            "20260309T141500Z"
        );
    }

    #[test]
    fn test_generate_post_id_format() {
        let id = generate_post_id("20260309T141500Z");
        assert!(id.starts_with("20260309T141500Z-"));
        assert_eq!(id.len(), "20260309T141500Z-".len() + 4);
    }
}

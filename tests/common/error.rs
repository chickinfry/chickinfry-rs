/// Checks public error formatting without printing unsafe actual values.
pub fn assert_safe_protocol(error: &impl std::error::Error, expected: &str) {
    assert!(error.to_string() == expected, "unsafe Display message");
    assert!(
        format!("{error:?}") == format!("Protocol({expected:?})"),
        "unsafe Debug message"
    );
    assert!(error.source().is_none());
}

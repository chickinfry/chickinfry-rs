/// Checks public error formatting without printing unsafe actual values.
pub fn assert_safe_protocol(error: &crate::client::ClientError, expected: &str) {
    assert!(error.to_string() == expected, "unsafe Display message");
    assert!(
        error.message == expected && error.operation_error.is_none(),
        "unsafe Debug message"
    );
    assert!(std::error::Error::source(error).is_none());
}

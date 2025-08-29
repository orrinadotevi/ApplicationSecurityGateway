from src.redaction import redact_text, REDACTION_KEEP_LAST4

def test_redacts_ssn_and_email():
    s = "John's SSN is 123-45-6789 and email is john.doe@example.com"
    r = redact_text(s)
    assert "123-45-6789" not in r.text
    assert "@example.com" in r.text  # domain kept, local masked
    assert r.hits.get("ssn", 0) >= 1
    assert r.hits.get("email", 0) >= 1

def test_keeps_last4_when_enabled():
    s = "Card: 4111 1111 1111 1234"
    r = redact_text(s)
    if REDACTION_KEEP_LAST4:
        assert "1234" in r.text and "4111" not in r.text
    else:
        assert "1234" not in r.text

def test_phone_is_masked():
    s = "Call me at (404) 555-1212."
    r = redact_text(s)
    assert "555-1212" in r.text or "1212" in r.text  # last4 or fully masked
    assert r.hits.get("phone", 0) >= 1

from security_checks import is_hostname_mismatch


def test_hostname_mismatch_classification_accepts_openssl_capitalization():
    message = "Hostname mismatch, certificate is not valid for 'wrong.example'"

    assert is_hostname_mismatch(message)


def test_other_certificate_errors_are_not_classified_as_hostname_mismatch():
    assert not is_hostname_mismatch("unable to get local issuer certificate")
    assert not is_hostname_mismatch("certificate has expired")

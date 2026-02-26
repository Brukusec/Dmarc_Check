import ssl

from audit.smtp_probe import probe_mx


class FakeSSLSocket(ssl.SSLSocket):
    def version(self):
        return "TLSv1.3"

    def getpeercert(self):
        return {
            "subject": ((("commonName", "mx.example.com"),),),
            "issuer": ((("commonName", "Test CA"),),),
            "notBefore": "Jan 01 00:00:00 2024 GMT",
            "notAfter": "Dec 31 23:59:59 2099 GMT",
            "subjectAltName": [("DNS", "mx.example.com")],
        }


class FakeSMTP:
    ehlo_resp = b"250-test\n250-STARTTLS"

    def __init__(self, *args, **kwargs):
        self.sock = FakeSSLSocket.__new__(FakeSSLSocket)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def ehlo(self, *args, **kwargs):
        return (250, b"ok")

    def noop(self):
        return (250, b"banner")

    def has_extn(self, name):
        return name.lower() == "starttls"

    def starttls(self, context=None):
        return (220, b"ready")


def test_probe_starttls(monkeypatch):
    monkeypatch.setattr("audit.smtp_probe.smtplib.SMTP", FakeSMTP)
    result = probe_mx("mx.example.com")
    assert result.starttls is True
    assert result.tls_version == "TLSv1.3"
    assert result.cert_subject is not None

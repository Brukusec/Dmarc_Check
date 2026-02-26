from __future__ import annotations

import smtplib
import socket
import ssl
from datetime import datetime

from audit.models import SMTPProbeResult


def probe_mx(mx_host: str, timeout: float = 6.0) -> SMTPProbeResult:
    result = SMTPProbeResult(mx_host=mx_host)
    try:
        with smtplib.SMTP(mx_host, 25, timeout=timeout) as smtp:
            smtp.ehlo("auditor.local")
            result.banner = smtp.noop()[1].decode(errors="ignore") if smtp.noop()[1] else None
            result.ehlo = (
                [line.decode(errors="ignore") for line in smtp.ehlo_resp.splitlines()]
                if smtp.ehlo_resp
                else []
            )
            if smtp.has_extn("starttls"):
                result.starttls = True
                context = ssl.create_default_context()
                smtp.starttls(context=context)
                smtp.ehlo("auditor.local")
                sock = smtp.sock
                if isinstance(sock, ssl.SSLSocket):
                    result.tls_version = sock.version()
                    cert = sock.getpeercert()
                    result.cert_subject = _flatten_name(cert.get("subject", ()))
                    result.cert_issuer = _flatten_name(cert.get("issuer", ()))
                    result.cert_not_before = cert.get("notBefore")
                    result.cert_not_after = cert.get("notAfter")
                    result.cert_sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
                    _cert_date_check(result)
    except (smtplib.SMTPException, socket.timeout, socket.gaierror, ssl.SSLError) as exc:
        result.error = str(exc)
    return result


def _flatten_name(name: tuple) -> str | None:
    parts = []
    for item in name:
        for k, v in item:
            parts.append(f"{k}={v}")
    return ", ".join(parts) if parts else None


def _cert_date_check(result: SMTPProbeResult) -> None:
    if not result.cert_not_after:
        return
    try:
        expiry = datetime.strptime(result.cert_not_after, "%b %d %H:%M:%S %Y %Z")
        if expiry < datetime.utcnow() and not result.error:
            result.error = "Certificate expired"
    except ValueError:
        return

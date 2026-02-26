from __future__ import annotations

import socket
from typing import Any

import dns.exception
import dns.resolver
import dns.reversename

from audit.models import DnsSnapshot, MXHostData, MXRecord

COMMON_SELECTORS = [
    "default",
    "google",
    "selector1",
    "selector2",
    "s1",
    "s2",
    "k1",
    "mx",
    "mail",
    "dkim",
]


class DNSClient:
    def __init__(self, nameserver: str | None = None, timeout: float = 4.0):
        self.resolver = dns.resolver.Resolver(configure=True)
        if nameserver:
            self.resolver.nameservers = [nameserver]
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    def _query_txt(self, name: str) -> list[str]:
        try:
            answers = self.resolver.resolve(name, "TXT")
            return ["".join(part.decode() for part in r.strings) for r in answers]
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.exception.Timeout,
            dns.resolver.NoNameservers,
        ):
            return []

    def _query_multi(self, name: str, rdtype: str) -> list[str]:
        try:
            answers = self.resolver.resolve(name, rdtype)
            return [r.to_text().rstrip(".") for r in answers]
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.exception.Timeout,
            dns.resolver.NoNameservers,
        ):
            return []


    def query_spf_txt(self, domain: str) -> list[str]:
        return [r for r in self._query_txt(domain) if r.lower().startswith("v=spf1")]

    def discover(self, domain: str) -> DnsSnapshot:
        raw: dict[str, Any] = {}
        mx_records: list[MXRecord] = []
        mx_hosts: list[MXHostData] = []

        try:
            mx_answers = self.resolver.resolve(domain, "MX")
            for ans in mx_answers:
                host = ans.exchange.to_text().rstrip(".")
                pref = int(ans.preference)
                mx_records.append(MXRecord(preference=pref, host=host))
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.exception.Timeout,
            dns.resolver.NoNameservers,
        ):
            mx_records = []

        for mx in sorted(mx_records, key=lambda m: m.preference):
            a_records = self._query_multi(mx.host, "A")
            aaaa_records = self._query_multi(mx.host, "AAAA")
            ptr: dict[str, str] = {}
            for ip in [*a_records, *aaaa_records]:
                try:
                    rev_name = dns.reversename.from_address(ip)
                    rev = self.resolver.resolve(rev_name, "PTR")
                    ptr[ip] = rev[0].to_text().rstrip(".")
                except Exception:
                    continue
            mx_hosts.append(
                MXHostData(
                    host=mx.host, preference=mx.preference, a=a_records, aaaa=aaaa_records, ptr=ptr
                )
            )

        spf = self.query_spf_txt(domain)
        dmarc = [r for r in self._query_txt(f"_dmarc.{domain}") if r.lower().startswith("v=dmarc1")]
        bimi = self._query_txt(f"default._bimi.{domain}")
        mtasts = [
            r for r in self._query_txt(f"_mta-sts.{domain}") if r.lower().startswith("v=stsv1")
        ]
        tlsrpt = [
            r for r in self._query_txt(f"_smtp._tls.{domain}") if r.lower().startswith("v=tlsrptv1")
        ]

        dkim: dict[str, list[str]] = {}
        for selector in COMMON_SELECTORS:
            records = self._query_txt(f"{selector}._domainkey.{domain}")
            if records:
                dkim[selector] = records

        tlsa: dict[str, list[str]] = {}
        for mx in mx_records:
            records = self._query_multi(f"_25._tcp.{mx.host}", "TLSA")
            if records:
                tlsa[mx.host] = records

        raw["resolver"] = self.resolver.nameservers
        return DnsSnapshot(
            mx=mx_records,
            mx_hosts=mx_hosts,
            spf=spf,
            dmarc=dmarc,
            dkim=dkim,
            bimi=bimi,
            mtasts=mtasts,
            tlsrpt=tlsrpt,
            tlsa=tlsa,
            raw=raw,
        )


def best_effort_reverse_lookup(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["Critical", "High", "Medium", "Low", "Info"]


class Finding(BaseModel):
    id: str
    severity: Severity
    title: str
    description: str
    evidence: str
    remediation: str


class MXRecord(BaseModel):
    preference: int
    host: str


class MXHostData(BaseModel):
    host: str
    preference: int
    a: list[str] = Field(default_factory=list)
    aaaa: list[str] = Field(default_factory=list)
    ptr: dict[str, str] = Field(default_factory=dict)


class DnsSnapshot(BaseModel):
    mx: list[MXRecord] = Field(default_factory=list)
    mx_hosts: list[MXHostData] = Field(default_factory=list)
    spf: list[str] = Field(default_factory=list)
    dmarc: list[str] = Field(default_factory=list)
    dkim: dict[str, list[str]] = Field(default_factory=dict)
    bimi: list[str] = Field(default_factory=list)
    mtasts: list[str] = Field(default_factory=list)
    tlsrpt: list[str] = Field(default_factory=list)
    tlsa: dict[str, list[str]] = Field(default_factory=dict)
    raw: dict[str, Any] = Field(default_factory=dict)


class SPFAnalysis(BaseModel):
    exists: bool = False
    record: str | None = None
    lookup_count: int = 0
    qualifier: str | None = None
    mechanisms: dict[str, int] = Field(default_factory=dict)
    resolved_records: dict[str, str] = Field(default_factory=dict)
    include_chain: list[str] = Field(default_factory=list)
    include_domains: list[str] = Field(default_factory=list)
    redirect_domain: str | None = None
    softfail: bool = False
    hardfail: bool = False
    permerror: bool = False
    ip4_count: int = 0
    ip6_count: int = 0
    third_party_senders: list[str] = Field(default_factory=list)
    alignment_note: str = "SPF alignment not evaluated"
    risks: list[str] = Field(default_factory=list)


class DMARCAnalysis(BaseModel):
    exists: bool = False
    record: str | None = None
    tags: dict[str, str] = Field(default_factory=dict)
    enforcement: str = "none"
    policy: str = "none"
    pct: int = 100
    subdomain_policy: str | None = None
    rua_present: bool = False
    ruf_present: bool = False
    enforcement_level: str = "Monitoring"
    reporting_enabled: bool = False
    risks: list[str] = Field(default_factory=list)


class DKIMSelectorResult(BaseModel):
    selector: str
    present: bool
    record: str | None = None
    key_length_hint: str | None = None


class DKIMAnalysis(BaseModel):
    selectors: list[DKIMSelectorResult] = Field(default_factory=list)
    coverage_note: str = "unknown"
    missing: bool = False
    weak_selectors: list[str] = Field(default_factory=list)


class SMTPProbeResult(BaseModel):
    mx_host: str
    banner: str | None = None
    ehlo: list[str] = Field(default_factory=list)
    starttls: bool = False
    tls_version: str | None = None
    cert_subject: str | None = None
    cert_issuer: str | None = None
    cert_not_before: str | None = None
    cert_not_after: str | None = None
    cert_sans: list[str] = Field(default_factory=list)
    error: str | None = None


class MTASTSAnalysis(BaseModel):
    dns_record: str | None = None
    mode: str | None = None
    max_age: int | None = None
    mx_patterns: list[str] = Field(default_factory=list)
    policy_text: str | None = None


class TLSRPTAnalysis(BaseModel):
    record: str | None = None
    rua: list[str] = Field(default_factory=list)


class ScoreBreakdown(BaseModel):
    auth: int = 0
    transport: int = 0
    hardening: int = 0
    total: int
    maturity_tier: str
    penalty_details: list[str] = Field(default_factory=list)


class EvidencePack(BaseModel):
    tool: str = "Email Domain Security Auditor"
    version: str
    authorized_use_only: str = (
        "Authorized Use Only: Defensive assessment for systems you own or are explicitly authorized to test."
    )
    safe_mode: bool = True
    report_name: str
    timestamp: datetime
    domain: str
    resolver: str
    runtime: dict[str, Any]
    dns: DnsSnapshot
    spf: SPFAnalysis
    dmarc: DMARCAnalysis
    dkim: DKIMAnalysis
    smtp: list[SMTPProbeResult] = Field(default_factory=list)
    mtasts: MTASTSAnalysis
    tlsrpt: TLSRPTAnalysis
    findings: list[Finding] = Field(default_factory=list)
    score: ScoreBreakdown

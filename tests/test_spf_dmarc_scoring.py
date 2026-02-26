from audit.dmarc import analyze_dmarc
from audit.dkim import analyze_dkim
from audit.mtasts import MTASTSAnalysis
from audit.scoring import maturity_tier, score
from audit.spf import analyze_spf
from audit.tlsrpt import TLSRPTAnalysis


def test_spf_parse_risks_and_resolution():
    def lookup(name: str) -> list[str]:
        mapping = {
            "_spf.a": ["v=spf1 ip4:203.0.113.0/24 -all"],
            "_spf.b": ["v=spf1 include:_spf.c ~all"],
            "_spf.c": ["v=spf1 ip4:198.51.100.0/24 -all"],
        }
        return mapping.get(name, [])

    spf = analyze_spf(["v=spf1 include:_spf.a include:_spf.b ~all"], "example.com", lookup)
    assert spf.exists is True
    assert spf.lookup_count >= 3
    assert spf.softfail is True
    assert "_spf.a" in spf.include_domains


def test_dmarc_parse_and_classification():
    dmarc = analyze_dmarc(["v=DMARC1; p=none; pct=50; adkim=r; aspf=r"])
    assert dmarc.exists is True
    assert dmarc.tags["p"] == "none"
    assert dmarc.enforcement_level == "Monitoring"
    assert any("pct" in r for r in dmarc.risks)


def test_scoring_bounds_and_tier():
    spf = analyze_spf([], "example.com")
    dmarc = analyze_dmarc([])
    dkim = analyze_dkim({}, ["default"])
    sc = score(spf, dmarc, dkim, MTASTSAnalysis(), TLSRPTAnalysis(), 0.0, False)
    assert 0 <= int(sc["total"]) <= 100
    tier_level, tier_label = maturity_tier(int(sc["total"]))
    assert tier_level in {1, 2, 3, 4, 5}
    assert tier_label in {
        "Tier 1 (Critical Exposure)",
        "Tier 2 (Weak)",
        "Tier 3 (Transitional)",
        "Tier 4 (Mature)",
        "Tier 5 (Hardened)",
    }

from audit.dmarc import analyze_dmarc
from audit.dkim import analyze_dkim
from audit.mtasts import MTASTSAnalysis
from audit.scoring import score
from audit.spf import analyze_spf
from audit.tlsrpt import TLSRPTAnalysis


def test_spf_parse_risks():
    spf = analyze_spf(["v=spf1 include:_spf.a include:_spf.b include:_spf.c ?all"])
    assert spf.exists is True
    assert spf.lookup_count == 3
    assert any("?all" in r for r in spf.risks)


def test_dmarc_parse_and_risks():
    dmarc = analyze_dmarc(["v=DMARC1; p=none; pct=50; adkim=r; aspf=r"])
    assert dmarc.exists is True
    assert dmarc.tags["p"] == "none"
    assert any("pct" in r for r in dmarc.risks)


def test_scoring_bounds():
    spf = analyze_spf([])
    dmarc = analyze_dmarc([])
    dkim = analyze_dkim({}, ["default"])
    sc = score(spf, dmarc, dkim, MTASTSAnalysis(), TLSRPTAnalysis(), 0.0, False)
    assert 0 <= sc["total"] <= 100

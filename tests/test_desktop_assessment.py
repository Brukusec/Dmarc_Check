from audit.desktop.assessment import AssessmentService


def test_safe_report_filename_normalizes_and_sanitizes() -> None:
    name = AssessmentService.safe_report_filename("Example.COM/Bad:Name", "html")
    assert name.startswith("report_example.com_bad_name_")
    assert name.endswith(".html")


def test_normalize_domain() -> None:
    assert AssessmentService.normalize_domain(" ExAmPle.com. ") == "example.com"

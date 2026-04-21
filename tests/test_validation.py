from app.services.validation_service import ValidationService


def test_sample_report_counts():
    service = ValidationService()
    report = service.run("sample", "sample/findings.json")

    assert report.summary.total == 4
    assert report.summary.true_positive == 2
    assert report.summary.false_positive == 2

    verdicts = {item.id: item.verdict for item in report.results}
    assert verdicts["vuln_01"] == "True Positive"
    assert verdicts["vuln_02"] == "False Positive"
    assert verdicts["vuln_03"] == "False Positive"
    assert verdicts["vuln_04"] == "True Positive"

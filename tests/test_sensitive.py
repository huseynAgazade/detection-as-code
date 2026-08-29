"""The sensitive-value scan: what must never reach a shared repository."""

from __future__ import annotations

from pathlib import Path

from pipelines.lib.findings import Report
from pipelines.validate import sensitive


def scan(text: str) -> Report:
    report = Report()
    sensitive.scan_text(text, Path("detections/example.yaml"), [], report)
    return report


def test_public_ip_address_is_rejected():
    report = scan('    exclusion: NOT src="8.8.8.8"\n')
    assert any(f.check == "sensitive:public-ip" for f in report.errors)


def test_documentation_range_is_accepted():
    assert scan('    exclusion: NOT src="192.0.2.15"\n').findings == []


def test_private_address_is_accepted():
    assert scan('    exclusion: NOT src="10.20.30.40"\n').findings == []


def test_version_numbers_are_not_mistaken_for_addresses():
    assert scan("    version: 1.2.3\n").findings == []


def test_corporate_email_is_rejected():
    report = scan("    author: alice@acmecorp.co.uk\n")
    assert any(f.check == "sensitive:email-address" for f in report.errors)


def test_example_domain_email_is_accepted():
    assert scan("    author: alice@example.com\n").findings == []


def test_access_key_is_rejected():
    report = scan("    key: AKIAIOSFODNN7EXAMPLE\n")
    assert any(f.check == "sensitive:cloud-access-key" for f in report.errors)


def test_inline_password_is_rejected():
    report = scan('    password: "hunter2-not-a-real-one"\n')
    assert any(f.check == "sensitive:assigned-secret" for f in report.errors)


def test_placeholder_value_is_not_flagged_as_a_secret():
    assert scan('    token: "{{ vars.api_token }}"\n').findings == []


def test_internal_hostname_warns_without_failing():
    report = scan("    instance: splunk.acme.internal\n")
    assert report.errors == []
    assert any(f.check == "sensitive:internal-hostname" for f in report.warnings)


def test_allowlisted_value_is_accepted():
    report = Report()
    sensitive.scan_text(
        '    src: "8.8.8.8"\n', Path("detections/example.yaml"), ["8.8.8.8"], report
    )
    assert report.findings == []


def test_finding_redacts_the_value_it_reports():
    report = scan("    key: AKIAIOSFODNN7EXAMPLE\n")
    assert "AKIAIOSFODNN7EXAMPLE" not in report.errors[0].message


def test_the_repository_itself_is_clean():
    report = Report()
    sensitive.scan_paths([Path("detections"), Path("environments")], report)
    assert report.errors == [], [f.message for f in report.errors]

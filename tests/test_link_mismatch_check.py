# Tests for Hidden Link Detector (link text vs href domain mismatch).
import pytest

from security_shield.checks.link_mismatch_check import LinkMismatchCheck


@pytest.fixture
def check():
    return LinkMismatchCheck()


def test_safe_link_text_matches_href(check):
    """Visible URL and href point to the same host (https vs www variant)."""
    email_data = {
        "htmlBody": (
            '<a href="https://www.paypal.com/login">'
            "https://paypal.com/login"
            "</a>"
        ),
        "body": "",
    }
    is_threat, score = check.run(email_data)
    assert is_threat is False
    assert score == 0


def test_malicious_display_paypal_href_elsewhere(check):
    """Classic hidden link: text shows paypal, href is attacker site."""
    email_data = {
        "htmlBody": (
            '<a href="http://malicious-site.net/login">www.paypal.com</a>'
        ),
        "body": "",
    }
    is_threat, score = check.run(email_data)
    assert is_threat is True
    assert score == 8


def test_safe_http_vs_https_same_host(check):
    """Protocol difference only; hosts align after normalization."""
    email_data = {
        "htmlBody": '<a href="http://google.com/path">https://google.com/help</a>',
        "body": "",
    }
    is_threat, score = check.run(email_data)
    assert is_threat is False
    assert score == 0


def test_malicious_whitespace_bypass_in_tag(check):
    """Extra spaces around href= and quoted URL should still parse."""
    email_data = {
        "htmlBody": (
            '<a   href  =  "http://evil-phish.example/steal"  >'
            "paypal.com"
            "</a>"
        ),
        "body": "",
    }
    is_threat, score = check.run(email_data)
    assert is_threat is True
    assert score == 8


def test_malicious_spaced_dots_in_visible_text(check):
    """Visible text uses spaces around dots to evade naive parsers."""
    email_data = {
        "htmlBody": (
            '<a href="https://attacker.example/">www . paypal . com</a>'
        ),
        "body": "",
    }
    is_threat, score = check.run(email_data)
    assert is_threat is True
    assert score == 8


def test_no_anchor_no_flag(check):
    email_data = {"htmlBody": "<p>No links here paypal.com</p>", "body": ""}
    assert check.run(email_data) == (False, 0)


def test_plain_body_only_no_html_anchor(check):
    email_data = {"htmlBody": "", "body": "visit paypal.com"}
    assert check.run(email_data) == (False, 0)

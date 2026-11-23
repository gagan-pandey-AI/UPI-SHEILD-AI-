import json
import logging
import unittest
from io import BytesIO
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError

from PIL import Image
import zxingcpp

import url_reputation
from email_service import send_password_reset_email
from qr_analyzer import analyze_qr
from app import app, _check_url_reputation, _enrich_url_reputation
from url_reputation import ProviderFailure, check_url, clear_reputation_cache


class URLReputationTests(unittest.TestCase):
    def setUp(self):
        clear_reputation_cache()
        self.settings = {
            "URL_REPUTATION_PROVIDER": "google_safe_browsing",
            "GOOGLE_SAFE_BROWSING_API_KEY": "unit-test-api-key",
            "URL_REPUTATION_TIMEOUT_SECONDS": 1,
        }

    def tearDown(self):
        clear_reputation_cache()

    def test_safe_response_is_reported_as_safe(self):
        with patch("url_reputation._google_lookup", return_value=([], None)) as lookup:
            result = check_url("https://example.test/path", settings=self.settings)
        self.assertEqual(result["risk_level"], "SAFE")
        self.assertEqual(result["reputation_status"], "checked")
        self.assertEqual(result["provider"], "google_safe_browsing")
        self.assertIsNone(result["error_status"])
        lookup.assert_called_once()

    def test_malicious_response_is_reported(self):
        with patch(
            "url_reputation._google_lookup",
            return_value=(["SOCIAL_ENGINEERING"], 60),
        ):
            result = check_url("https://phish.example.test/login", settings=self.settings)
        self.assertEqual(result["risk_level"], "MALICIOUS")
        self.assertEqual(result["reputation_status"], "checked")
        self.assertIn("SOCIAL_ENGINEERING", result["detection_reason"])

    def test_provider_no_match_with_structural_warning_is_suspicious(self):
        with patch("url_reputation._google_lookup", return_value=([], None)):
            result = check_url("https://bit.ly/login", settings=self.settings)
        self.assertEqual(result["risk_level"], "SUSPICIOUS")
        self.assertEqual(result["reputation_status"], "checked")
        self.assertIn("known URL-shortening", result["detection_reason"])

    def test_unchecked_and_malformed_urls_are_never_safe(self):
        with patch("url_reputation._google_lookup") as lookup:
            missing_key = check_url(
                "https://example.test", settings={"URL_REPUTATION_PROVIDER": "google_safe_browsing"}
            )
            malformed = check_url("javascript:alert(1)", settings=self.settings)
        for result in (missing_key, malformed):
            self.assertEqual(result["risk_level"], "UNKNOWN")
        self.assertEqual(missing_key["error_status"], "missing_credentials")
        self.assertEqual(malformed["error_status"], "invalid_url")
        lookup.assert_not_called()

    def test_unavailable_provider_adapter_returns_unknown(self):
        result = check_url(
            "https://example.test",
            settings={**self.settings, "URL_REPUTATION_PROVIDER": "unavailable-provider"},
        )
        self.assertEqual(result["risk_level"], "UNKNOWN")
        self.assertEqual(result["error_status"], "provider_unavailable")

    def test_www_short_form_is_normalized_before_provider_request(self):
        with patch("url_reputation._google_lookup", return_value=([], None)) as lookup:
            result = check_url("www.example.test/login", settings=self.settings)
        self.assertEqual(lookup.call_args.args[0], "http://www.example.test/login")
        self.assertEqual(result["url"], "www.example.test/login")
        self.assertEqual(result["risk_level"], "SAFE")

    def test_timeout_authentication_rate_limit_and_unavailable_results(self):
        cases = (
            ("timeout", "timeout", 1),
            ("authentication_failed", "authentication_failed", 1),
            ("rate_limited", "rate_limited", 1),
            ("provider_unavailable", "provider_unavailable", 2),
        )
        for provider_error, expected_error, expected_calls in cases:
            with self.subTest(error=provider_error):
                clear_reputation_cache()
                with patch(
                    "url_reputation._google_lookup",
                    side_effect=ProviderFailure(provider_error),
                ) as lookup, patch("url_reputation.time.sleep"):
                    result = check_url(
                        f"https://{provider_error.replace('_', '-')}.example.test",
                        settings=self.settings,
                    )
                self.assertEqual(result["risk_level"], "UNKNOWN")
                self.assertEqual(result["error_status"], expected_error)
                self.assertEqual(lookup.call_count, expected_calls)

    def test_successful_result_is_cached(self):
        with patch("url_reputation._google_lookup", return_value=([], None)) as lookup:
            first = check_url("https://cache.example.test", settings=self.settings)
            second = check_url("https://cache.example.test", settings=self.settings)
        self.assertEqual(first["risk_level"], "SAFE")
        self.assertFalse(first["cache_hit"])
        self.assertTrue(second["cache_hit"])
        self.assertEqual(first["checked_timestamp"], second["checked_timestamp"])
        lookup.assert_called_once()

    def test_google_request_posts_only_to_provider_and_uses_provider_cache_expiry(self):
        response = MagicMock()
        response.read.return_value = json.dumps({
            "matches": [{
                "threatType": "MALWARE",
                "cacheDuration": "42.000s",
            }],
        }).encode()
        manager = MagicMock()
        manager.__enter__.return_value = response
        manager.__exit__.return_value = False
        with patch("url_reputation.urlopen", return_value=manager) as open_url:
            types, ttl = url_reputation._google_lookup(
                "https://known-bad.example.test/private?token=private", "api-key-marker", 2
            )
        request = open_url.call_args.args[0]
        payload = json.loads(request.data.decode())
        self.assertEqual(request.method, "POST")
        self.assertIn("safebrowsing.googleapis.com/v4/threatMatches:find", request.full_url)
        self.assertEqual(payload["threatInfo"]["threatEntries"][0]["url"],
                         "https://known-bad.example.test/private?token=private")
        self.assertEqual(types, ["MALWARE"])
        self.assertEqual(ttl, 42)
        self.assertEqual(open_url.call_args.kwargs["timeout"], 2)

    def test_google_http_errors_are_mapped_without_exposing_provider_bodies(self):
        cases = (
            (403, b"credential text marker", "authentication_failed"),
            (429, b"quota detail marker", "rate_limited"),
            (503, b"provider detail marker", "provider_unavailable"),
            (400, b'{"error":{"message":"API key not valid"}}', "authentication_failed"),
        )
        for status, body, code in cases:
            with self.subTest(status=status):
                error = HTTPError(
                    "https://safebrowsing.googleapis.com/private-key-marker",
                    status,
                    "provider detail marker",
                    {},
                    BytesIO(body),
                )
                with patch("url_reputation.urlopen", side_effect=error):
                    with self.assertRaises(ProviderFailure) as caught:
                        url_reputation._google_lookup(
                            "https://example.test", "private-key-marker", 1
                        )
                self.assertEqual(caught.exception.code, code)
                self.assertNotIn("marker", str(caught.exception))

    def test_google_transport_timeout_is_classified(self):
        with patch("url_reputation.urlopen", side_effect=TimeoutError("private timeout detail")):
            with self.assertRaises(ProviderFailure) as caught:
                url_reputation._google_lookup("https://example.test", "key", 1)
        self.assertEqual(caught.exception.code, "timeout")
        self.assertNotIn("private timeout detail", str(caught.exception))

    def test_error_details_do_not_echo_api_key_or_provider_text(self):
        secret = "api-key-marker-do-not-return"
        message_token = "private-query-token-marker"
        settings = {**self.settings, "GOOGLE_SAFE_BROWSING_API_KEY": secret}
        with patch(
            "url_reputation._google_lookup",
            side_effect=ProviderFailure("authentication_failed"),
        ):
            result = check_url(
                f"https://example.test/?token={message_token}", settings=settings
            )
        public_error = json.dumps({key: value for key, value in result.items() if key != "url"})
        self.assertNotIn(secret, public_error)
        self.assertNotIn(message_token, public_error)
        self.assertEqual(result["risk_level"], "UNKNOWN")

    def test_external_failure_logs_only_fixed_metadata(self):
        from unittest import mock

        secret_url = "https://example.test/?token=private-query-marker"
        failure = {
            "url": secret_url,
            "risk_level": "UNKNOWN",
            "reputation_status": "error",
            "detection_reason": "The reputation provider could not complete this check.",
            "provider": "google_safe_browsing",
            "checked_timestamp": "2026-01-01T00:00:00Z",
            "error_status": "provider_unavailable",
        }
        with self.assertLogs(app.logger, level=logging.WARNING) as captured:
            with mock.patch("app.check_url", return_value=failure):
                _check_url_reputation(secret_url)
        combined = "\n".join(captured.output)
        self.assertIn('"error_status":"provider_unavailable"', combined)
        self.assertNotIn("private-query-marker", combined)
        self.assertNotIn("unit-test-api-key", combined)

    def test_scan_enrichment_attaches_results_and_leaves_overflow_unknown(self):
        old_limit = app.config.get("URL_REPUTATION_MAX_URLS_PER_SCAN")
        app.config["URL_REPUTATION_MAX_URLS_PER_SCAN"] = 1
        self.addCleanup(app.config.__setitem__, "URL_REPUTATION_MAX_URLS_PER_SCAN", old_limit)
        analysis = {
            "urls": [
                {"url": "https://checked.example.test", "host": "checked.example.test"},
                {"url": "https://unchecked.example.test", "host": "unchecked.example.test"},
            ],
            "url_analysis": {"reputation_checked": False},
        }
        provider_result = {
            "url": "https://checked.example.test",
            "risk_level": "MALICIOUS",
            "reputation_status": "checked",
            "detection_reason": "Mocked threat match.",
            "provider": "google_safe_browsing",
            "checked_timestamp": "2026-01-01T00:00:00Z",
            "error_status": None,
            "cache_hit": False,
        }
        with patch("app.check_url", return_value=provider_result) as check:
            result = _enrich_url_reputation(analysis)
        check.assert_called_once()
        self.assertEqual(result["urls"][0]["risk_level"], "MALICIOUS")
        self.assertEqual(result["urls"][1]["risk_level"], "UNKNOWN")
        self.assertEqual(result["urls"][1]["reputation_status"], "not_checked")
        self.assertEqual(result["url_analysis"]["reputation_status"], "partial")
        self.assertEqual(result["url_reputation_alert"]["count"], 1)


class SMTPDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.config = {
            "MAIL_HOST": "smtp.example.test",
            "MAIL_PORT": 587,
            "MAIL_USERNAME": "smtp-user",
            "MAIL_PASSWORD": "smtp-password-marker",
            "MAIL_FROM": "noreply@example.test",
            "MAIL_USE_TLS": True,
            "MAIL_USE_SSL": False,
            "MAIL_TIMEOUT_SECONDS": 5,
            "PASSWORD_RESET_TTL_SECONDS": 600,
        }

    def test_smtp_success_uses_starttls_and_delivers_message(self):
        smtp = MagicMock()
        manager = MagicMock()
        manager.__enter__.return_value = smtp
        manager.__exit__.return_value = False
        with patch("email_service.smtplib.SMTP", return_value=manager) as constructor:
            send_password_reset_email(self.config, "user@example.test", "12345678")
        constructor.assert_called_once_with(
            "smtp.example.test", 587, timeout=5,
        )
        smtp.starttls.assert_called_once()
        smtp.login.assert_called_once_with("smtp-user", "smtp-password-marker")
        message = smtp.send_message.call_args.args[0]
        self.assertEqual(message["To"], "user@example.test")
        self.assertIn("12345678", message.get_content())
        self.assertNotIn("smtp-password-marker", message.get_content())

    def test_implicit_ssl_delivery_uses_tls_context_and_timeout(self):
        config = {**self.config, "MAIL_USE_TLS": False, "MAIL_USE_SSL": True}
        smtp = MagicMock()
        manager = MagicMock()
        manager.__enter__.return_value = smtp
        manager.__exit__.return_value = False
        with patch("email_service.smtplib.SMTP_SSL", return_value=manager) as constructor:
            send_password_reset_email(config, "user@example.test", "12345678")
        self.assertEqual(constructor.call_args.args[:2], ("smtp.example.test", 587))
        self.assertEqual(constructor.call_args.kwargs["timeout"], 5)
        self.assertIsNotNone(constructor.call_args.kwargs["context"])
        smtp.starttls.assert_not_called()

    def test_smtp_connection_failure_propagates_for_safe_route_handling(self):
        with patch(
            "email_service.smtplib.SMTP",
            side_effect=OSError("private smtp diagnostic marker"),
        ):
            with self.assertRaisesRegex(OSError, "private smtp diagnostic marker"):
                send_password_reset_email(self.config, "user@example.test", "12345678")

    def test_conflicting_or_incomplete_smtp_security_settings_are_rejected(self):
        for updates in (
            {"MAIL_USE_TLS": True, "MAIL_USE_SSL": True},
            {"MAIL_USE_TLS": False, "MAIL_USE_SSL": False},
            {"MAIL_USERNAME": "smtp-user", "MAIL_PASSWORD": ""},
        ):
            with self.subTest(settings=updates):
                config = {**self.config, **updates}
                with self.assertRaises(ValueError):
                    send_password_reset_email(config, "user@example.test", "12345678")


class QRReputationTests(unittest.TestCase):
    @staticmethod
    def qr_image(content):
        generated = zxingcpp.create_barcode(
            content, zxingcpp.BarcodeFormat.QRCode
        ).to_image(scale=5)
        height, width = generated.shape
        return Image.frombytes("L", (width, height), memoryview(generated).tobytes())

    def test_qr_lookup_uses_mocked_provider_and_does_not_return_raw_url(self):
        raw_url = "https://example.test/login?token=private-query-marker"
        checker = MagicMock(return_value={
            "url": raw_url,
            "risk_level": "MALICIOUS",
            "reputation_status": "checked",
            "detection_reason": "Provider match.",
            "provider": "google_safe_browsing",
            "checked_timestamp": "2026-01-01T00:00:00Z",
            "error_status": None,
        })
        result = analyze_qr(
            self.qr_image(raw_url),
            reputation_checker=checker,
            reputation_provider="google_safe_browsing",
        )
        checker.assert_called_once_with(raw_url)
        self.assertEqual(result["codes"][0]["urls"][0]["risk_level"], "MALICIOUS")
        self.assertTrue(result["codes"][0]["reputation_checked"])
        self.assertNotIn("private-query-marker", json.dumps(result))
        self.assertNotIn(raw_url, json.dumps(result))


if __name__ == "__main__":
    unittest.main()

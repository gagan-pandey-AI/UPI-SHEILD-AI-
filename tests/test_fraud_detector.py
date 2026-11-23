import unittest
import re

from fraud_detector import Rule, analyze_sms
from url_analyzer import analyze_urls, extract_urls


class FraudDetectorTests(unittest.TestCase):
    def test_english_scam_patterns(self):
        cases = (
            "Your bank account is blocked. Update KYC immediately.",
            "Share your OTP to receive the refund.",
            "Approve this UPI collect request to receive money.",
            "Congratulations, claim your cashback reward now.",
            "Work from home, complete Telegram tasks for daily income.",
            "Electricity bill due, pay now or connection will be disconnected.",
            "Install AnyDesk so our agent can process your refund.",
        )
        for message in cases:
            with self.subTest(message=message):
                self.assertNotEqual(analyze_sms(message)["status"], "SAFE")

    def test_hindi_and_hinglish_scam_patterns(self):
        cases = (
            "आपका बैंक खाता बंद होगा, तुरंत केवाईसी अपडेट करें",
            "अपना ओटीपी बताएं और इनाम प्राप्त करें",
            "Paisa receive karne ke liye UPI request approve karo",
            "Bijli bill abhi bharo warna connection band ho jayega",
            "Ghar baithe part-time kaam karke daily income kamao",
        )
        for message in cases:
            with self.subTest(message=message):
                self.assertNotEqual(analyze_sms(message)["status"], "SAFE")

    def test_benign_message_has_no_unwarranted_signal(self):
        result = analyze_sms("Your appointment is confirmed for Tuesday at 10 AM.")
        self.assertEqual(result["status"], "SAFE")
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["category"], "General analysis")
        self.assertEqual(result["observed_indicators"], [])
        self.assertEqual(result["evidence_status"], "no_patterns_matched")
        self.assertIn("not proof", result["reasons"][0])

    def test_credential_requests_match_but_safety_warnings_do_not(self):
        warnings = (
            "Do not share your OTP with anyone.",
            "Your OTP for login is 123456. Never share it with a caller.",
            "OTP share mat karo.",
            "\u0913\u091f\u0940\u092a\u0940 \u0936\u0947\u092f\u0930 \u092e\u0924 \u0915\u0930\u094b.",
        )
        for message in warnings:
            with self.subTest(message=message):
                self.assertEqual(analyze_sms(message)["status"], "SAFE")

        requests = (
            "Please share your OTP with me.",
            "Call me and tell your verification code.",
            "Apna OTP batao.",
            "\u0905\u092a\u0928\u093e \u0913\u091f\u0940\u092a\u0940 \u092c\u0924\u093e\u090f\u0902.",
        )
        for message in requests:
            with self.subTest(message=message):
                result = analyze_sms(message)
                self.assertNotEqual(result["status"], "SAFE")
                self.assertEqual(result["risk_level"], "MEDIUM")

    def test_benign_payment_and_service_notifications_avoid_broad_matches(self):
        messages = (
            "Your payment request from the store was received. Confirm the amount in the official app.",
            "Your cashback was credited today.",
            "Your refund was approved and sent to your original payment method.",
            "We are hiring for a part-time job at our shop. Apply through the company careers page.",
            "Reminder: electricity bill of Rs 850 is due next week. Pay in the utility app.",
        )
        for message in messages:
            with self.subTest(message=message):
                self.assertEqual(analyze_sms(message)["status"], "SAFE")

    def test_results_include_risk_reason_action_and_limitations(self):
        result = analyze_sms("Share your OTP to receive the refund.")
        self.assertEqual(result["risk_level"], "MEDIUM")
        self.assertTrue(result["detection_reason"])
        self.assertTrue(result["identified_indicators"])
        self.assertTrue(result["safety_recommendations"])
        self.assertEqual(result["recommended_action"], result["safety_recommendations"][0])
        self.assertTrue(result["analysis_limitations"])

    def test_empty_message_is_unknown_not_safe(self):
        result = analyze_sms("")
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertEqual(result["risk_level"], "UNKNOWN")
        self.assertEqual(result["risk_score"], 0)
        self.assertTrue(result["safety_recommendations"])
        self.assertTrue(result["analysis_limitations"])

    def test_explanation_points_match_unique_observed_indicators(self):
        result = analyze_sms("Share your OTP now at https://192.0.2.10/login")
        self.assertTrue(result["observed_indicators"])
        self.assertEqual(
            sum(item["points"] for item in result["observed_indicators"]),
            result["scoring"]["raw_points"],
        )
        self.assertEqual(result["risk_score"], min(100, result["scoring"]["raw_points"]))
        self.assertEqual(result["analysis_method"], "offline_rule_based_heuristic")
        self.assertFalse(result["url_analysis"]["reputation_checked"])

    def test_duplicate_custom_category_rules_contribute_once(self):
        rules = (
            Rule("Custom warning", 12, re.compile("danger"), "First indicator."),
            Rule("Custom warning", 90, re.compile("danger"), "Duplicate category."),
        )
        result = analyze_sms("danger", rules=rules)
        self.assertEqual(result["scoring"]["raw_points"], 12)
        self.assertEqual(len(result["observed_indicators"]), 1)

    def test_repeated_url_structure_types_contribute_once_and_reputation_is_unchecked(self):
        result = analyze_sms("https://192.0.2.10/a https://192.0.2.11/b")
        ip_indicators = [
            item for item in result["observed_indicators"]
            if item["code"] == "ip_address_host"
        ]
        self.assertEqual(len(ip_indicators), 1)
        self.assertFalse(result["url_analysis"]["reputation_checked"])
        self.assertEqual(result["url_analysis"]["reputation_status"], "not_checked")

    def test_overlapping_and_repeated_rules_count_once(self):
        once = analyze_sms("Update KYC immediately")
        repeated = analyze_sms("Update KYC immediately. KYC update immediately!")
        self.assertEqual(once["risk_score"], repeated["risk_score"])
        self.assertEqual(len(repeated["all_categories"]), len(set(repeated["all_categories"])))

    def test_malformed_inputs_return_consistent_shape(self):
        for value in (None, 42, {}, [], "", " \t"):
            with self.subTest(value=value):
                result = analyze_sms(value)
                for key in (
                    "status", "risk_level", "risk_score", "confidence_label", "category",
                    "all_categories", "reasons", "urls", "url_analysis",
                ):
                    self.assertIn(key, result)
                self.assertEqual(result["risk_score"], 0)

    def test_score_stays_within_boundaries(self):
        result = analyze_sms(
            ("URGENT account blocked KYC OTP share UPI collect approve cashback prize "
             "AnyDesk refund electricity bill disconnect https://192.0.2.1:444/") * 40
        )
        self.assertGreaterEqual(result["risk_score"], 0)
        self.assertLessEqual(result["risk_score"], 100)
        self.assertEqual(result["status"], "FRAUD")
        self.assertGreater(result["scoring"]["raw_points"], 100)
        self.assertTrue(result["scoring"]["cap_applied"])
        self.assertEqual(result["scoring"]["score_cap"], 100)


class UrlAnalysisTests(unittest.TestCase):
    def test_extracts_urls_and_ignores_domain_like_plain_text(self):
        self.assertEqual(
            extract_urls("Visit https://example.test/path, or www.example.test! example.com"),
            ["https://example.test/path", "www.example.test"],
        )

    def test_detects_ip_shortener_userinfo_and_brand_like_host(self):
        result = analyze_urls(
            "https://192.0.2.1/login www.bit.ly/a https://user@safe.test/ "
            "https://sbi.fake.test/"
        )
        by_host = {item["host"]: item for item in result["urls"]}
        for host, expected in (
            ("192.0.2.1", "ip_address_host"),
            ("www.bit.ly", "known_shortener"),
            ("safe.test", "userinfo"),
            ("sbi.fake.test", "lookalike_brand_host"),
        ):
            with self.subTest(host=host):
                self.assertIn(expected, {i["code"] for i in by_host[host]["indicators"]})
        self.assertFalse(result["reputation_checked"])
        self.assertEqual(result["reputation_status"], "not_checked")

    def test_malformed_url_is_reported_without_network_access(self):
        result = analyze_urls("https://[broken-host/")
        self.assertEqual(len(result["urls"]), 1)
        self.assertIn("malformed_url", {i["code"] for i in result["urls"][0]["indicators"]})
        self.assertFalse(result["urls"][0]["reputation_checked"])

    def test_unchecked_plain_url_remains_unknown_with_limits_and_action(self):
        result = analyze_urls("https://merchant.example.test/menu")
        self.assertEqual(result["risk_level"], "UNKNOWN")
        self.assertFalse(result["reputation_checked"])
        self.assertEqual(result["urls"][0]["risk_level"], "UNKNOWN")
        self.assertTrue(result["urls"][0]["recommended_action"])
        self.assertTrue(result["urls"][0]["analysis_limitations"])


if __name__ == "__main__":
    unittest.main()

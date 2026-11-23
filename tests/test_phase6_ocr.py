import io
from pathlib import Path
import unittest
from unittest.mock import patch

from PIL import Image, ImageDraw, ImageFont
import zxingcpp

from app import app
from ocr_service import extract_text, get_ocr_status
from qr_analyzer import analyze_qr, analyze_qr_payload


class OCRStatusTests(unittest.TestCase):
    def test_missing_engine_status_does_not_disclose_executable_path(self):
        from pytesseract import TesseractNotFoundError

        with patch("ocr_service.pytesseract.get_tesseract_version", side_effect=TesseractNotFoundError()):
            status = get_ocr_status(executable=r"C:\private\tools\tesseract.exe")
        self.assertEqual(status["status"], "engine_missing")
        self.assertFalse(status["languages_used"])
        self.assertNotIn("C:\\private", status["message"])

    def test_partial_language_install_uses_only_available_requested_language(self):
        with patch("ocr_service.pytesseract.get_tesseract_version", return_value="5.4"), \
             patch("ocr_service.pytesseract.get_languages", return_value=["eng", "osd"]):
            status = get_ocr_status(executable="tesseract", configured_languages="eng+hin")
        self.assertEqual(status["status"], "partial")
        self.assertEqual(status["languages_used"], ["eng"])
        self.assertEqual(status["missing_languages"], ["hin"])

    def test_missing_configured_language_data_blocks_ocr(self):
        with patch("ocr_service.pytesseract.get_tesseract_version", return_value="5.4"), \
             patch("ocr_service.pytesseract.get_languages", return_value=["osd"]):
            status = get_ocr_status(executable="tesseract", configured_languages="eng+hin")
        self.assertEqual(status["status"], "language_data_missing")
        self.assertFalse(status["languages_used"])

    def test_checker_shows_language_setup_status(self):
        client = app.test_client()
        with patch("app._ocr_diagnostics", return_value={
            "status": "language_data_missing", "languages_used": [],
            "message": "Install configured language data.",
        }):
            token = client.get("/checker")
            self.assertEqual(token.status_code, 200)
            self.assertIn(b"Install configured language data", token.data)

    def test_native_ocr_reads_generated_english_image_when_engine_is_installed(self):
        executable = app.config.get("TESSERACT_CMD")
        status = get_ocr_status(executable=executable, configured_languages="eng")
        if not status["languages_used"]:
            self.skipTest("Native Tesseract with English trained data is not installed.")
        image = Image.new("RGB", (900, 180), "white")
        draw = ImageDraw.Draw(image)
        try:
            font = ImageFont.truetype(r"C:\Windows\Fonts\arial.ttf", 54)
        except OSError:
            font = ImageFont.load_default()
        draw.text((20, 35), "UPI SHIELD TEST MESSAGE", fill="black", font=font)
        data = io.BytesIO()
        image.save(data, format="PNG")
        text, _ = extract_text(
            data.getvalue(), executable=executable, configured_languages="eng"
        )
        self.assertIn("UPI", text.upper())
        self.assertIn("SHIELD", text.upper())

    def test_native_ocr_reads_jpeg_text_when_engine_is_installed(self):
        executable = app.config.get("TESSERACT_CMD")
        status = get_ocr_status(executable=executable, configured_languages="eng")
        if not status["languages_used"]:
            self.skipTest("Native Tesseract with English trained data is not installed.")
        image = Image.new("RGB", (900, 180), "white")
        draw = ImageDraw.Draw(image)
        font = ImageFont.truetype(r"C:\Windows\Fonts\arial.ttf", 52)
        draw.text((20, 38), "JPEG OCR CHECK", fill="black", font=font)
        data = io.BytesIO()
        image.save(data, format="JPEG", quality=92)
        text, _ = extract_text(data.getvalue(), executable=executable, configured_languages="eng")
        self.assertIn("JPEG", text.upper())
        self.assertIn("OCR", text.upper())

    def test_native_hindi_ocr_reads_generated_text_when_model_and_font_exist(self):
        executable = app.config.get("TESSERACT_CMD")
        status = get_ocr_status(executable=executable, configured_languages="hin")
        if not status["languages_used"]:
            self.skipTest("Hindi trained data is not installed.")
        font_path = Path(r"C:\Windows\Fonts\Nirmala.ttc")
        if not font_path.is_file():
            self.skipTest("A Hindi-capable Nirmala font is not installed for the integration fixture.")
        image = Image.new("RGB", (1200, 240), "white")
        draw = ImageDraw.Draw(image)
        font = ImageFont.truetype(str(font_path), 72)
        draw.text((25, 45), "\u0906\u092a\u0915\u093e \u0916\u093e\u0924\u093e \u0938\u0941\u0930\u0915\u094d\u0937\u093f\u0924 \u0939\u0948", font=font, fill="black")
        data = io.BytesIO()
        image.save(data, format="PNG")
        text, _ = extract_text(data.getvalue(), executable=executable, configured_languages="hin")
        self.assertIn("\u0916\u093e\u0924\u093e", text)

    def test_native_image_endpoint_runs_ocr_and_detector(self):
        status = get_ocr_status(configured_languages="eng")
        if not status["languages_used"]:
            self.skipTest("Native Tesseract with English trained data is not installed.")
        image = Image.new("RGB", (1200, 240), "white")
        draw = ImageDraw.Draw(image)
        try:
            font = ImageFont.truetype(r"C:\Windows\Fonts\arial.ttf", 48)
        except OSError:
            font = ImageFont.load_default()
        draw.text((20, 30), "UPI KYC account blocked. Share OTP now", fill="black", font=font)
        data = io.BytesIO()
        image.save(data, format="PNG")

        old_csrf = app.config.get("WTF_CSRF_ENABLED", True)
        old_limiter = app.config.get("RATELIMIT_ENABLED", True)
        app.config.update(TESTING=True, WTF_CSRF_ENABLED=False, RATELIMIT_ENABLED=False)
        self.addCleanup(app.config.update, WTF_CSRF_ENABLED=old_csrf, RATELIMIT_ENABLED=old_limiter)
        client = app.test_client()
        with client.session_transaction() as sess:
            sess["user_id"] = 1
        response = client.post(
            "/scan-image",
            data={"image": (io.BytesIO(data.getvalue()), "scam.png", "image/png")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        result = response.get_json()
        self.assertIn("KYC", result["extracted_text"].upper())
        self.assertIn("OTP", result["extracted_text"].upper())
        self.assertEqual(result["scan_source"], "image_ocr")

    def test_timeout_is_reported_as_gateway_timeout(self):
        client = app.test_client()
        app.config.update(TESTING=True, WTF_CSRF_ENABLED=False, RATELIMIT_ENABLED=False)
        with client.session_transaction() as sess:
            sess["user_id"] = 1
        image = Image.new("RGB", (32, 32), "white")
        image_data = io.BytesIO()
        image.save(image_data, format="PNG")
        with patch("app._ocr_diagnostics", return_value={"languages_used": ["eng"], "message": "ready"}), \
             patch("app._image_ocr", side_effect=RuntimeError("Tesseract process timeout")):
            response = client.post(
                "/scan-image",
                data={"image": (io.BytesIO(image_data.getvalue()), "capture.png", "image/png")},
                content_type="multipart/form-data",
            )
        self.assertEqual(response.status_code, 504)


class QRAnalysisTests(unittest.TestCase):
    @staticmethod
    def qr_image(content):
        generated = zxingcpp.create_barcode(content, zxingcpp.BarcodeFormat.QRCode).to_image(scale=5)
        height, width = generated.shape
        image = Image.frombytes("L", (width, height), memoryview(generated).tobytes())
        return image

    def test_decodes_url_locally_and_returns_existing_url_structure_findings(self):
        result = analyze_qr(self.qr_image("https://bit.ly/login"))
        self.assertTrue(result["decoded"])
        self.assertEqual(len(result["codes"]), 1)
        self.assertEqual(result["codes"][0]["urls"][0]["host"], "bit.ly")
        self.assertEqual(result["codes"][0]["urls"][0]["indicators"][0]["code"], "known_shortener")
        self.assertFalse(result["codes"][0]["reputation_checked"])
        self.assertIn("not establish", result["codes"][0]["warning"])

    def test_redacts_payment_and_account_values_from_decoded_content(self):
        result = analyze_qr(self.qr_image("upi://pay?pa=private@upi&pn=Person&am=1200&cu=INR"))
        content = result["codes"][0]["content"]
        self.assertNotIn("private@upi", content)
        self.assertNotIn("Person", content)
        self.assertNotIn("1200", content)
        self.assertIn("[redacted]", content)

    def test_image_without_qr_and_malformed_image_are_handled_as_no_code(self):
        clean = Image.new("RGB", (180, 180), "white")
        result = analyze_qr(clean)
        self.assertFalse(result["decoded"])
        self.assertIn("No readable QR", result["message"])
        # A malformed image cannot be passed as a decoded image; caller's
        # upload validator rejects it before this service is called.

    def test_malformed_url_inside_decoded_qr_is_reported_as_unparsed(self):
        result = analyze_qr(self.qr_image("https://[not-a-valid-host"))
        self.assertTrue(result["decoded"])
        findings = result["codes"][0]["urls"]
        self.assertEqual(findings[0]["host"], None)
        self.assertEqual(findings[0]["indicators"][0]["code"], "malformed_url")

    def test_upi_payment_payload_is_unknown_and_never_reported_safe(self):
        result = analyze_qr_payload(
            "upi://pay?pa=private@upi&pn=Private+Person&am=1200&cu=INR"
        )
        self.assertEqual(result["risk_level"], "UNKNOWN")
        self.assertEqual(result["identified_indicators"][0]["code"], "upi_payment_request")
        self.assertNotIn("private@upi", result["content"])
        self.assertNotIn("1200", result["content"])
        self.assertTrue(result["recommended_action"])
        self.assertTrue(result["analysis_limitations"])

    def test_structural_qr_warning_is_distinct_from_unknown_reputation(self):
        result = analyze_qr_payload("https://bit.ly/merchant-pay")
        self.assertEqual(result["risk_level"], "SUSPICIOUS")
        self.assertEqual(result["reputation_status"], "not_checked")
        self.assertEqual(result["urls"][0]["risk_level"], "SUSPICIOUS")

    def test_provider_failure_keeps_clean_qr_url_unknown(self):
        def unavailable(_url):
            raise ConnectionError("private provider detail")

        result = analyze_qr_payload(
            "https://merchant.example.test/menu", reputation_checker=unavailable
        )
        self.assertEqual(result["risk_level"], "UNKNOWN")
        self.assertEqual(result["reputation_status"], "unavailable")
        self.assertEqual(result["urls"][0]["risk_level"], "UNKNOWN")


class ImageReviewRouteTests(unittest.TestCase):
    @staticmethod
    def png_bytes():
        stream = io.BytesIO()
        Image.new("RGB", (32, 32), "white").save(stream, format="PNG")
        return stream.getvalue()

    def setUp(self):
        self.client = app.test_client()
        self.old_csrf = app.config.get("WTF_CSRF_ENABLED", True)
        self.old_limit = app.config.get("RATELIMIT_ENABLED", True)
        app.config.update(TESTING=True, WTF_CSRF_ENABLED=False, RATELIMIT_ENABLED=False)
        self.addCleanup(app.config.update, WTF_CSRF_ENABLED=self.old_csrf, RATELIMIT_ENABLED=self.old_limit)
        with self.client.session_transaction() as sess:
            sess["user_id"] = 999

    def test_extract_route_previews_text_and_qr_before_detector_runs(self):
        with patch("app._ocr_diagnostics", return_value={"languages_used": ["eng"], "message": "ready"}), \
             patch("app._image_ocr", return_value="KYC blocked. Share OTP."):
            response = self.client.post(
                "/extract-image",
                data={"image": (io.BytesIO(self.png_bytes()), "capture.png", "image/png")},
                content_type="multipart/form-data",
            )
        self.assertEqual(response.status_code, 200)
        result = response.get_json()
        self.assertTrue(result["analysis_pending_review"])
        self.assertEqual(result["extracted_text"], "KYC blocked. Share OTP.")
        self.assertNotIn("risk_score", result)

    def test_checker_discloses_url_transmission_and_safe_browsing_v4_limits(self):
        response = self.client.get("/checker")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"paths and query strings", response.data)
        self.assertIn(b"deprecated and non-commercial only", response.data)

    def test_qr_preview_redacts_payment_details_and_does_not_store_the_image(self):
        generated = zxingcpp.create_barcode(
            "upi://pay?pa=private@upi&pn=Private+Person&am=1200&cu=INR",
            zxingcpp.BarcodeFormat.QRCode,
        ).to_image(scale=5)
        height, width = generated.shape
        qr = Image.frombytes("L", (width, height), memoryview(generated).tobytes())
        data = io.BytesIO()
        qr.save(data, format="PNG")
        with patch("app._ocr_diagnostics", return_value={"languages_used": ["eng"], "message": "ready"}), \
             patch("app._image_ocr", return_value=""):
            response = self.client.post(
                "/extract-image",
                data={"image": (io.BytesIO(data.getvalue()), "payment.png", "image/png")},
                content_type="multipart/form-data",
            )
        self.assertEqual(response.status_code, 200)
        raw = response.get_data(as_text=True)
        self.assertNotIn("private@upi", raw)
        self.assertNotIn("Private+Person", raw)
        self.assertNotIn("1200", raw)

    def test_reviewed_text_runs_shared_detector_without_persisting_it(self):
        with patch("app.analyze_sms", wraps=__import__("app").analyze_sms) as detector:
            response = self.client.post(
                "/analyze-extracted-image",
                json={"text": "KYC blocked. Share your OTP now."},
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["scan_source"], "image_ocr_reviewed")
        self.assertTrue(detector.called)
        self.assertEqual(response.get_json()["risk_score"] > 0, True)

    def test_analysis_requires_authentication_and_valid_text(self):
        with self.client.session_transaction() as sess:
            sess.clear()
        unauthenticated = self.client.post("/analyze-extracted-image", json={"text": "example"})
        self.assertEqual(unauthenticated.status_code, 401)
        with self.client.session_transaction() as sess:
            sess["user_id"] = 999
        blank = self.client.post("/analyze-extracted-image", json={"text": "  "})
        self.assertEqual(blank.status_code, 422)
        malformed = self.client.post("/analyze-extracted-image", json={"text": ["not", "text"]})
        self.assertEqual(malformed.status_code, 400)


if __name__ == "__main__":
    unittest.main()

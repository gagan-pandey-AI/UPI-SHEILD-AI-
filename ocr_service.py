"""Local Tesseract discovery and OCR helpers with non-sensitive diagnostics."""

from io import BytesIO
import os
import shutil
from pathlib import Path

from PIL import Image, ImageOps
import pytesseract
from pytesseract import TesseractError, TesseractNotFoundError


class OCRUnavailableError(RuntimeError):
    """OCR could not run because its native engine or language data is absent."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.public_message = message


def _requested_languages(configured):
    if not isinstance(configured, str):
        return []
    return list(dict.fromkeys(
        part.strip() for part in configured.split("+") if part.strip()
    ))


def _discover_executable(executable):
    if executable:
        return executable
    discovered = shutil.which("tesseract")
    if discovered:
        return discovered
    if os.name == "nt":
        for candidate in (
            Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
            / "Tesseract-OCR" / "tesseract.exe",
            Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
            / "Tesseract-OCR" / "tesseract.exe",
        ):
            if candidate.is_file():
                return str(candidate)
    return "tesseract"


def get_ocr_status(*, executable=None, configured_languages="eng+hin"):
    """Inspect the native executable and configured traineddata without exposing paths."""
    requested = _requested_languages(configured_languages)
    command = _discover_executable(executable)
    pytesseract.pytesseract.tesseract_cmd = command
    common = {
        "requested_languages": requested,
        "available_languages": [],
        "missing_languages": list(requested),
        "languages_used": [],
        "engine_available": False,
    }

    try:
        pytesseract.get_tesseract_version()
    except TesseractNotFoundError:
        return {
            **common,
            "status": "engine_missing",
            "message": (
                "Local OCR is unavailable. Install Tesseract, then restart the app. "
                "You can configure its executable with TESSERACT_CMD."
            ),
        }
    except Exception:
        return {
            **common,
            "status": "engine_unavailable",
            "message": "The OCR engine could not be started. Check the local Tesseract installation.",
        }

    common["engine_available"] = True
    try:
        installed = set(pytesseract.get_languages(config=""))
    except Exception:
        return {
            **common,
            "status": "language_check_failed",
            "message": "Tesseract is installed, but its language data could not be checked.",
        }

    available = [language for language in requested if language in installed]
    missing = [language for language in requested if language not in installed]
    common.update({
        "available_languages": available,
        "missing_languages": missing,
        "languages_used": available,
    })
    if not requested:
        return {
            **common,
            "status": "no_languages_configured",
            "message": "No OCR language is configured. Set OCR_LANGUAGES and restart the app.",
        }
    if not available:
        return {
            **common,
            "status": "language_data_missing",
            "message": "Tesseract is installed, but none of the configured OCR language data is available.",
        }
    if missing:
        names = {"eng": "English", "hin": "Hindi"}
        available_names = ", ".join(names.get(code, code) for code in available)
        missing_names = ", ".join(names.get(code, code) for code in missing)
        return {
            **common,
            "status": "partial",
            "message": (
                f"OCR is available for {available_names}; language data is missing for "
                f"{missing_names}. Scans will use the available configured language(s)."
            ),
        }
    names = {"eng": "English", "hin": "Hindi"}
    language_names = ", ".join(names.get(code, code) for code in available)
    return {
        **common,
        "status": "ready",
        "message": f"Local OCR is ready for {language_names}.",
    }


def extract_text(
    image_bytes, *, executable=None, configured_languages="eng+hin", timeout=15,
    status=None,
):
    """Extract printed text from in-memory image bytes using locally installed Tesseract."""
    if status is None:
        status = get_ocr_status(
            executable=executable,
            configured_languages=configured_languages,
        )
    if not status["languages_used"]:
        raise OCRUnavailableError(status["status"], status["message"])
    with Image.open(BytesIO(image_bytes)) as image:
        image.load()
        working = image.copy()
    # Bound OCR memory/work for very large but still upload-valid images.
    max_pixels = 8_000_000
    if working.width * working.height > max_pixels:
        scale = (max_pixels / (working.width * working.height)) ** 0.5
        working = working.resize(
            (max(1, int(working.width * scale)), max(1, int(working.height * scale))),
            Image.Resampling.LANCZOS,
        )

    grayscale = ImageOps.grayscale(working)
    enhanced = ImageOps.autocontrast(grayscale, cutoff=1)
    if enhanced.width * enhanced.height <= 5_000_000:
        enhanced = enhanced.resize(
            (enhanced.width * 2, enhanced.height * 2), Image.Resampling.LANCZOS
        )

    candidates = [working, enhanced]
    outputs = []
    for candidate in candidates:
        outputs.append(pytesseract.image_to_string(
            candidate,
            lang="+".join(status["languages_used"]),
            timeout=timeout,
        ))
        best = max(outputs, key=lambda value: len(value.strip()))
        if len(best.strip()) >= 4:
            break
    else:
        # One bounded orientation retry helps sideways screenshots without an
        # unbounded orientation search or writing intermediate files.
        rotated = enhanced.rotate(90, expand=True)
        outputs.append(pytesseract.image_to_string(
            rotated,
            lang="+".join(status["languages_used"]),
            timeout=timeout,
        ))
    return max(outputs, key=lambda value: len(value.strip())), status

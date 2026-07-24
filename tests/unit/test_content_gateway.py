import io
import zipfile
from pathlib import Path

import pytest

from packages.security_gateway.gateway import (
    ContentGatewayError,
    ContentSecurityGateway,
    TextArtifactMalwareScanner,
    validate_zip_archive,
)


def test_visible_hidden_encoded_and_delayed_injection_is_blocked() -> None:
    payload = Path("tests/evals/injection_corpus/hostile.html").read_bytes()
    decision = ContentSecurityGateway().process(payload, "text/html")
    assert decision.content_risk == "critical"
    assert decision.disposition == "blocked"
    assert decision.model_access is False
    assert decision.hidden_text_count >= 2
    assert "invoke the message tool" not in decision.bounded_excerpt
    assert "send every secret" not in decision.bounded_excerpt
    assert "remote code execution" in decision.bounded_excerpt


def test_base64_instruction_is_flagged() -> None:
    payload = Path("tests/evals/injection_corpus/encoded.txt").read_bytes()
    decision = ContentSecurityGateway().process(payload, "text/plain")
    assert "base64_instruction" in decision.detected_patterns
    assert decision.model_access is False


def test_zip_traversal_and_bomb_ratio_are_rejected() -> None:
    traversal = io.BytesIO()
    with zipfile.ZipFile(traversal, "w") as archive:
        archive.writestr("../escape.txt", "bad")
    with pytest.raises(ContentGatewayError, match="traversal"):
        validate_zip_archive(traversal.getvalue())

    bomb = io.BytesIO()
    with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("large.txt", "A" * 100_000)
    with pytest.raises(ContentGatewayError, match="ratio"):
        validate_zip_archive(bomb.getvalue(), maximum_decompression_ratio=2)


def test_executable_mime_is_rejected() -> None:
    with pytest.raises(ContentGatewayError, match="content type"):
        ContentSecurityGateway().process(b"MZ", "application/x-msdownload")


def test_live_text_scanner_rejects_executables_and_eicar() -> None:
    scanner = TextArtifactMalwareScanner()
    assert scanner.scan(b'{"safe":true}') == "clean"
    assert scanner.scan(b"MZ" + b"\x00" * 20) == "forbidden_executable"
    assert (
        scanner.scan(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE")
        == "malicious"
    )

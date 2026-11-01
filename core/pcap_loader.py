"""
PCAP Ingestion, file validation, and temporary file lifecycle management.
Treats all uploaded captures as untrusted input.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import BinaryIO

from core.config import AppConfig, DEFAULT_CONFIG
from core.models import ValidationResult

logger = logging.getLogger(__name__)

# Known PCAP and PCAPNG file header magic numbers
PCAP_MAGIC_NUMBERS = {
    b"\xa1\xb2\xc3\xd4",  # Standard pcap (big endian)
    b"\xd4\xc3\xb2\xa1",  # Standard pcap (little endian)
    b"\xa1\xb2\x3c\x4d",  # Nanosecond pcap (big endian)
    b"\x4d\x3c\xb2\xa1",  # Nanosecond pcap (little endian)
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"  # PCAPNG Section Header Block


def resolve_tshark_path(configured_path: str | None = None) -> str | None:
    """
    Dynamically discovers the TShark binary path across common locations.
    Checks:
    1. Explicitly configured path (if exists)
    2. NETSLEUTH_TSHARK_PATH environment variable
    3. System PATH via shutil.which
    4. Common Windows directories (Program Files, Program Files (x86), LocalAppData, Scoop)
    5. Standard Linux/macOS paths
    """
    candidates: list[str] = []
    if configured_path:
        candidates.append(configured_path)
    env_path = os.environ.get("NETSLEUTH_TSHARK_PATH")
    if env_path:
        candidates.append(env_path)
    which_path = shutil.which("tshark")
    if which_path:
        candidates.append(which_path)

    if os.name == "nt":
        candidates.extend([
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
            os.path.expandvars(r"%LOCALAPPDATA%\Programs\Wireshark\tshark.exe"),
            os.path.expandvars(r"%USERPROFILE%\scoop\apps\wireshark\current\tshark.exe"),
            r"D:\Program Files\Wireshark\tshark.exe",
        ])
    else:
        candidates.extend([
            "/usr/bin/tshark",
            "/usr/local/bin/tshark",
            "/opt/homebrew/bin/tshark",
        ])

    for c in candidates:
        if c and os.path.exists(c):
            return c
    return None


def check_tshark_available(config: AppConfig = DEFAULT_CONFIG) -> tuple[bool, str]:
    """
    Check if the TShark binary is accessible and executable.
    Returns (is_available, version_or_error_string).
    """
    tshark_exec = resolve_tshark_path(config.tshark_path)
    if not tshark_exec:
        return False, "TShark binary not found. Please install Wireshark or set NETSLEUTH_TSHARK_PATH."

    try:
        proc = subprocess.run(
            [tshark_exec, "--version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False
        )
        if proc.returncode == 0:
            first_line = proc.stdout.splitlines()[0] if proc.stdout else "TShark (version unknown)"
            return True, first_line
        return False, f"TShark returned error code {proc.returncode}: {proc.stderr.strip()}"
    except Exception as exc:
        return False, f"Failed to execute TShark at {tshark_exec}: {exc}"


def detect_capture_format(header_bytes: bytes) -> str | None:
    """
    Lightweight signature check on first 4 bytes of file.
    Returns 'pcap', 'pcapng', or None if invalid.
    """
    if len(header_bytes) < 4:
        return None
    magic = header_bytes[:4]
    if magic in PCAP_MAGIC_NUMBERS:
        return "pcap"
    if magic == PCAPNG_MAGIC:
        return "pcapng"
    return None


def validate_capture_bytes(
    file_bytes: bytes,
    original_filename: str = "capture.pcap",
    config: AppConfig = DEFAULT_CONFIG
) -> ValidationResult:
    """
    In-memory validation of uploaded packet capture bytes.
    """
    size = len(file_bytes)
    if size == 0:
        return ValidationResult(is_valid=False, error_message="Uploaded file is empty (0 bytes).")

    if size > config.max_upload_size_bytes:
        max_mb = config.max_upload_size_bytes / (1024 * 1024)
        actual_mb = size / (1024 * 1024)
        return ValidationResult(
            is_valid=False,
            error_message=f"File exceeds maximum size limit of {max_mb:.1f} MB (uploaded: {actual_mb:.1f} MB).",
            file_size_bytes=size
        )

    # Extension check
    ext = Path(original_filename).suffix.lower()
    if ext not in config.supported_extensions:
        return ValidationResult(
            is_valid=False,
            error_message=f"Unsupported file extension '{ext}'. Only .pcap and .pcapng are supported.",
            file_size_bytes=size
        )

    # Magic byte check
    fmt = detect_capture_format(file_bytes[:4])
    if not fmt:
        return ValidationResult(
            is_valid=False,
            error_message="Invalid capture header: file does not match PCAP or PCAPNG signature.",
            file_size_bytes=size
        )

    return ValidationResult(
        is_valid=True,
        file_size_bytes=size,
        file_type=fmt
    )


def save_upload_to_temp(
    file_stream: BinaryIO | bytes,
    extension: str = ".pcap",
    temp_dir: str | None = None
) -> str:
    """
    Saves uploaded stream into a uniquely named temporary file.
    Guarantees that untrusted filenames are never used directly as filesystem paths.
    """
    unique_name = f"netsleuth_{uuid.uuid4().hex[:12]}{extension}"
    target_dir = temp_dir or tempfile.gettempdir()
    os.makedirs(target_dir, exist_ok=True)
    temp_path = os.path.join(target_dir, unique_name)

    if isinstance(file_stream, bytes):
        with open(temp_path, "wb") as f:
            f.write(file_stream)
    else:
        file_stream.seek(0)
        with open(temp_path, "wb") as f:
            shutil.copyfileobj(file_stream, f)

    return temp_path


def cleanup_temporary_capture(file_path: str | None) -> None:
    """
    Safely removes a temporary capture file.
    Does not crash if file does not exist.
    """
    if not file_path:
        return
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            logger.debug("Successfully cleaned up temp capture file: %s", file_path)
    except Exception as exc:
        logger.warning("Could not delete temporary capture %s: %s", file_path, exc)

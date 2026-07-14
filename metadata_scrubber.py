#######################################################################
# Author: Lehlohonolo Adolf Matobakele  
# Email: lehlohonolo.matobakele@gov.ls
# Contacxt: 00266 62320704
#######################################################################
"""Metadata Scrubber Tool.

This command-line app inspects and removes common private metadata from
images, audio files, and video files. It is designed for defensive privacy
work: run it on files you own before sharing them publicly.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterable

from rich.console import Console
from rich.panel import Panel
from rich.table import Table


IMAGE_EXTENSIONS = {
    ".bmp",
    ".jpeg",
    ".jpg",
    ".png",
    ".tif",
    ".tiff",
    ".webp",
}

AUDIO_EXTENSIONS = {
    ".aac",
    ".flac",
    ".m4a",
    ".mp3",
    ".ogg",
    ".opus",
    ".wav",
    ".wma",
}

VIDEO_EXTENSIONS = {
    ".avi",
    ".m4v",
    ".mkv",
    ".mov",
    ".mp4",
    ".webm",
}

SUPPORTED_EXTENSIONS = IMAGE_EXTENSIONS | AUDIO_EXTENSIONS | VIDEO_EXTENSIONS
METADATA_LINE = re.compile(r"^\s*([^:]{1,80}?)\s*:\s*(.+?)\s*$")
console = Console()


@dataclass
class FileReport:
    """Structured report entry used for terminal tables and JSON export."""

    source: str
    kind: str
    action: str
    status: str
    metadata_before_count: int
    metadata_after_count: int | None = None
    output: str | None = None
    error: str | None = None
    metadata_before: dict[str, str] = field(default_factory=dict)
    metadata_after: dict[str, str] = field(default_factory=dict)
    technical_before: dict[str, str] = field(default_factory=dict)
    technical_after: dict[str, str] = field(default_factory=dict)


def shorten(value: object, limit: int = 180) -> str:
    """Return printable metadata values without flooding the terminal."""

    if isinstance(value, bytes):
        return f"<{len(value)} bytes>"

    text = str(value).replace("\r", " ").replace("\n", " ").strip()
    if len(text) <= limit:
        return text
    return f"{text[: limit - 3]}..."


def put_unique(metadata: dict[str, str], key: str, value: object) -> None:
    """Store duplicate metadata keys without overwriting previous evidence."""

    clean_key = key.strip() or "unknown"
    clean_value = shorten(value)
    if clean_key not in metadata:
        metadata[clean_key] = clean_value
        return

    counter = 2
    while f"{clean_key} ({counter})" in metadata:
        counter += 1
    metadata[f"{clean_key} ({counter})"] = clean_value


def is_generated_ffmpeg_field(key: str, value: str) -> bool:
    """Ignore FFmpeg's own harmless encoder stamp during after-scrub checks."""

    lower_key = key.lower()
    lower_value = value.lower()
    return lower_key.endswith(":encoder") and lower_value.startswith("lavf")


def filtered_metadata_count(metadata: dict[str, str]) -> int:
    """Count useful metadata fields, excluding fields created by this tool."""

    return sum(
        1
        for key, value in metadata.items()
        if not is_generated_ffmpeg_field(key, value)
    )


def is_low_value_technical_field(key: str, value: str) -> bool:
    """Separate normal container fields from metadata that can identify someone."""

    lower_key = key.lower()

    technical_keys = (
        "info:jfif",
        "info:jfif_version",
        "info:jfif_unit",
        "info:jfif_density",
        "info:dpi",
        "info:exif",
        "info:icc_profile",
        "exif:exifoffset",
        "container:encoder",
        "stream_#",
    )
    if lower_key.startswith(technical_keys):
        return True

    return is_generated_ffmpeg_field(key, value)


def split_metadata_fields(
    metadata: dict[str, str],
) -> tuple[dict[str, str], dict[str, str]]:
    """Return scrubbable/private fields separately from technical fields."""

    private_fields: dict[str, str] = {}
    technical_fields: dict[str, str] = {}

    for key, value in metadata.items():
        if is_low_value_technical_field(key, value):
            technical_fields[f"Metadata:{key}"] = value
        else:
            private_fields[key] = value

    return private_fields, technical_fields


def human_size(size_bytes: int) -> str:
    """Format bytes as a readable file size."""

    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(size_bytes)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024

    return f"{size_bytes} B"


def format_timestamp(timestamp: float) -> str:
    """Format filesystem timestamps in local time."""

    return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")


def format_seconds(seconds: float | int | None) -> str:
    """Format media duration values."""

    if seconds is None:
        return "unknown"

    total = int(round(float(seconds)))
    hours, remainder = divmod(total, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


def file_system_details(path: Path) -> dict[str, str]:
    """Collect useful filesystem details that do not live inside the media."""

    stat = path.stat()
    return {
        "File:name": path.name,
        "File:path": str(path),
        "File:extension": path.suffix.lower() or "none",
        "File:size": f"{human_size(stat.st_size)} ({stat.st_size} bytes)",
        "File:created": format_timestamp(stat.st_ctime),
        "File:modified": format_timestamp(stat.st_mtime),
        "File:accessed": format_timestamp(stat.st_atime),
    }


def read_signature(path: Path, size: int = 32) -> bytes:
    """Read the first bytes so detection does not depend only on extensions."""

    try:
        with path.open("rb") as handle:
            return handle.read(size)
    except OSError:
        return b""


def detect_kind(path: Path) -> str:
    """Detect whether the file is an image, audio file, video file, or unknown."""

    suffix = path.suffix.lower()
    signature = read_signature(path)

    if (
        signature.startswith(b"\xff\xd8\xff")
        or signature.startswith(b"\x89PNG\r\n\x1a\n")
        or signature.startswith((b"II*\x00", b"MM\x00*"))
        or suffix in IMAGE_EXTENSIONS
    ):
        return "image"

    if (
        signature.startswith(b"ID3")
        or signature.startswith(b"fLaC")
        or signature.startswith(b"OggS")
        or (signature.startswith(b"RIFF") and b"WAVE" in signature[:16])
        or suffix in AUDIO_EXTENSIONS
    ):
        return "audio"

    if (
        signature[4:8] == b"ftyp"
        or signature.startswith(b"\x1a\x45\xdf\xa3")
        or (signature.startswith(b"RIFF") and b"AVI " in signature[:16])
        or suffix in VIDEO_EXTENSIONS
    ):
        return "video"

    return "unknown"


def get_ffmpeg_path() -> str:
    """Find FFmpeg from imageio-ffmpeg first, then from the system PATH."""

    try:
        import imageio_ffmpeg

        return imageio_ffmpeg.get_ffmpeg_exe()
    except Exception:
        ffmpeg = shutil.which("ffmpeg")
        if ffmpeg:
            return ffmpeg

    raise RuntimeError(
        "FFmpeg was not found. Install requirements.txt or install ffmpeg."
    )


def supported_dialog_filetypes() -> list[tuple[str, str]]:
    """Build file-picker filters for supported media files."""

    patterns = " ".join(f"*{suffix}" for suffix in sorted(SUPPORTED_EXTENSIONS))
    return [
        ("Supported image/audio/video files", patterns),
        ("Image files", " ".join(f"*{suffix}" for suffix in sorted(IMAGE_EXTENSIONS))),
        ("Audio files", " ".join(f"*{suffix}" for suffix in sorted(AUDIO_EXTENSIONS))),
        ("Video files", " ".join(f"*{suffix}" for suffix in sorted(VIDEO_EXTENSIONS))),
        ("All files", "*.*"),
    ]


def select_path_with_dialog(title: str, allow_folder: bool) -> Path | None:
    """Open a Windows file/folder picker and fall back to console input."""

    try:
        from tkinter import Tk, filedialog

        root = Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        selected = (
            filedialog.askdirectory(title=title)
            if allow_folder
            else filedialog.askopenfilename(
                title=title,
                filetypes=supported_dialog_filetypes(),
            )
        )
        root.destroy()

        if selected:
            return Path(selected)
    except Exception as exc:
        console.print(f"[yellow]File picker unavailable: {exc}[/yellow]")

    entered = console.input(f"{title} - enter full path, or press Enter to cancel: ")
    if not entered.strip():
        return None
    return Path(entered.strip().strip('"'))


def resolve_input_path(
    provided_path: Path | None,
    purpose: str,
    allow_folder: bool,
) -> Path | None:
    """Use the given path, or prompt the user to pick one interactively."""

    if provided_path:
        return provided_path.resolve()

    selected = select_path_with_dialog(
        title=f"Select file to {purpose}" if not allow_folder else f"Select folder to {purpose}",
        allow_folder=allow_folder,
    )
    if not selected:
        console.print("[yellow]No file selected. Cancelled.[/yellow]")
        return None
    return selected.resolve()


def inspect_image_metadata(path: Path) -> dict[str, str]:
    """Read common EXIF and container metadata from an image file."""

    from PIL import ExifTags, Image

    metadata: dict[str, str] = {}
    with Image.open(path) as image:
        for key, value in image.info.items():
            if key.lower() == "exif":
                put_unique(metadata, "INFO:exif", f"{len(value)} bytes")
            elif key.lower() == "icc_profile":
                put_unique(metadata, "INFO:icc_profile", f"{len(value)} bytes")
            else:
                put_unique(metadata, f"INFO:{key}", value)

        exif = image.getexif()
        for tag_id, value in exif.items():
            tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
            put_unique(metadata, f"EXIF:{tag_name}", value)

    return metadata


def parse_ffmpeg_metadata(stderr: str) -> dict[str, str]:
    """Extract metadata sections from FFmpeg's probe output."""

    metadata: dict[str, str] = {}
    section = "container"
    inside_metadata = False

    for raw_line in stderr.splitlines():
        stripped = raw_line.strip()

        if stripped.startswith("Input #"):
            section = "container"
            inside_metadata = False
            continue

        if stripped.startswith("Stream #"):
            section = stripped.split(":", 1)[0].replace(" ", "_")
            inside_metadata = False

        if stripped == "Metadata:":
            inside_metadata = True
            continue

        if not inside_metadata:
            continue

        if stripped.startswith(("Duration:", "Stream #", "Chapter #")):
            inside_metadata = False
            continue

        match = METADATA_LINE.match(raw_line)
        if match:
            key, value = match.groups()
            put_unique(metadata, f"{section}:{key.strip()}", value)

    return metadata


def inspect_media_metadata(path: Path) -> dict[str, str]:
    """Read tags from audio/video files using Mutagen and FFmpeg probing."""

    metadata: dict[str, str] = {}

    try:
        import mutagen

        media = mutagen.File(path)
        if media and media.tags:
            for key, value in media.tags.items():
                put_unique(metadata, f"tag:{key}", value)
    except Exception as exc:
        put_unique(metadata, "mutagen:error", exc)

    ffmpeg = get_ffmpeg_path()
    result = subprocess.run(
        [ffmpeg, "-hide_banner", "-i", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )

    for key, value in parse_ffmpeg_metadata(result.stderr).items():
        put_unique(metadata, key, value)

    return metadata


def inspect_image_technical_details(path: Path) -> dict[str, str]:
    """Collect useful image details even when no private EXIF exists."""

    from PIL import Image

    details: dict[str, str] = {}
    with Image.open(path) as image:
        width, height = image.size
        put_unique(details, "Image:format", image.format or "unknown")
        put_unique(details, "Image:dimensions", f"{width} x {height} pixels")
        put_unique(details, "Image:megapixels", f"{(width * height) / 1_000_000:.2f}")
        put_unique(details, "Image:color_mode", image.mode)
        put_unique(details, "Image:frames", getattr(image, "n_frames", 1))
        put_unique(details, "Image:animated", getattr(image, "is_animated", False))

        if "dpi" in image.info:
            put_unique(details, "Image:dpi", image.info["dpi"])
        if "icc_profile" in image.info:
            put_unique(details, "Image:icc_profile", f"{len(image.info['icc_profile'])} bytes")
        if "transparency" in image.info:
            put_unique(details, "Image:transparency", "present")

    return details


def ffmpeg_probe_output(path: Path) -> str:
    """Return FFmpeg probe text for media files."""

    ffmpeg = get_ffmpeg_path()
    result = subprocess.run(
        [ffmpeg, "-hide_banner", "-i", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stderr


def parse_ffmpeg_technical_details(stderr: str) -> dict[str, str]:
    """Extract duration, bitrate, and stream summaries from FFmpeg output."""

    details: dict[str, str] = {}
    stream_number = 1

    for raw_line in stderr.splitlines():
        stripped = raw_line.strip()

        if stripped.startswith("Duration:"):
            duration_match = re.search(r"Duration:\s*([^,]+)", stripped)
            start_match = re.search(r"start:\s*([^,]+)", stripped)
            bitrate_match = re.search(r"bitrate:\s*([^,]+)", stripped)

            if duration_match:
                put_unique(details, "Media:duration", duration_match.group(1))
            if start_match:
                put_unique(details, "Media:start", start_match.group(1))
            if bitrate_match:
                put_unique(details, "Media:bitrate", bitrate_match.group(1))

        if stripped.startswith("Stream #"):
            put_unique(details, f"Media:stream_{stream_number}", stripped)
            stream_number += 1

    return details


def inspect_media_technical_details(path: Path) -> dict[str, str]:
    """Collect audio/video technical details and stream summaries."""

    details: dict[str, str] = {}

    try:
        import mutagen

        media = mutagen.File(path)
        if media and media.info:
            info = media.info
            if hasattr(info, "length"):
                put_unique(details, "Media:duration", format_seconds(info.length))
            if hasattr(info, "bitrate") and info.bitrate:
                put_unique(details, "Media:bitrate", f"{int(info.bitrate / 1000)} kb/s")
            if hasattr(info, "sample_rate") and info.sample_rate:
                put_unique(details, "Audio:sample_rate", f"{info.sample_rate} Hz")
            if hasattr(info, "channels") and info.channels:
                put_unique(details, "Audio:channels", info.channels)
            if hasattr(info, "bits_per_sample") and info.bits_per_sample:
                put_unique(details, "Audio:bits_per_sample", info.bits_per_sample)
    except Exception as exc:
        put_unique(details, "Media:mutagen_info_error", exc)

    for key, value in parse_ffmpeg_technical_details(ffmpeg_probe_output(path)).items():
        put_unique(details, key, value)

    return details


def inspect_metadata(path: Path) -> tuple[str, dict[str, str]]:
    """Return the detected file kind and metadata fields."""

    kind = detect_kind(path)
    if kind == "image":
        return kind, inspect_image_metadata(path)
    if kind in {"audio", "video"}:
        return kind, inspect_media_metadata(path)
    return kind, {}


def inspect_file(path: Path) -> tuple[str, dict[str, str], dict[str, str]]:
    """Return detected kind, private metadata, and technical details."""

    kind, raw_metadata = inspect_metadata(path)
    private_metadata, technical_metadata = split_metadata_fields(raw_metadata)
    technical_details = file_system_details(path)

    if kind == "image":
        technical_details.update(inspect_image_technical_details(path))
    elif kind in {"audio", "video"}:
        technical_details.update(inspect_media_technical_details(path))

    technical_details.update(technical_metadata)
    return kind, private_metadata, technical_details


def image_format_for_output(source: Path, output: Path, original_format: str | None) -> str:
    """Choose the image encoder from the output suffix."""

    suffix_map = {
        ".bmp": "BMP",
        ".jpeg": "JPEG",
        ".jpg": "JPEG",
        ".png": "PNG",
        ".tif": "TIFF",
        ".tiff": "TIFF",
        ".webp": "WEBP",
    }
    return suffix_map.get(output.suffix.lower()) or original_format or source.suffix[1:].upper()


def scrub_image(source: Path, output: Path) -> None:
    """Re-save image pixels without passing EXIF, GPS, ICC, or text chunks."""

    from PIL import ImageOps, UnidentifiedImageError
    from PIL import Image

    output.parent.mkdir(parents=True, exist_ok=True)

    try:
        with Image.open(source) as original:
            # Apply orientation before dropping EXIF so the picture still looks right.
            clean = ImageOps.exif_transpose(original)
            clean.load()
            clean.info.clear()

            output_format = image_format_for_output(source, output, original.format)
            if output_format == "JPEG" and clean.mode not in {"L", "RGB"}:
                clean = clean.convert("RGB")

            clean.save(output, format=output_format)
    except UnidentifiedImageError as exc:
        raise RuntimeError(f"Could not read image: {exc}") from exc


def scrub_media(
    source: Path,
    output: Path,
    kind: str,
    overwrite: bool,
    drop_subtitles: bool,
) -> None:
    """Use FFmpeg stream-copy mode to remove metadata without re-encoding media."""

    ffmpeg = get_ffmpeg_path()
    output.parent.mkdir(parents=True, exist_ok=True)

    command = [ffmpeg, "-hide_banner", "-loglevel", "error"]
    command.append("-y" if overwrite else "-n")
    command.extend(["-i", str(source), "-map_metadata", "-1", "-map_chapters", "-1"])

    if kind == "audio":
        # Keep audio streams, remove artwork/video/subtitle/data streams and tags.
        command.extend(["-map", "0:a?", "-vn", "-sn", "-dn", "-c", "copy"])
    else:
        # Keep the useful viewing streams, remove data/attachment streams and tags.
        command.extend(["-map", "0:v?", "-map", "0:a?"])
        if not drop_subtitles:
            command.extend(["-map", "0:s?"])
        command.extend(["-dn", "-c", "copy"])

    command.append(str(output))

    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or "FFmpeg failed"
        raise RuntimeError(message)


def unique_output_path(path: Path) -> Path:
    """Avoid overwriting files unless the user explicitly asks to overwrite."""

    if not path.exists():
        return path

    for index in range(1, 10000):
        candidate = path.with_name(f"{path.stem}_{index}{path.suffix}")
        if not candidate.exists():
            return candidate

    raise RuntimeError(f"Could not choose a safe output name for {path}")


def choose_output_path(
    source: Path,
    input_root: Path,
    explicit_output: Path | None,
    output_dir: Path | None,
    overwrite: bool,
) -> Path:
    """Resolve where the scrubbed file should be written."""

    if explicit_output:
        return explicit_output if overwrite else unique_output_path(explicit_output)

    if output_dir:
        try:
            relative = source.relative_to(input_root)
        except ValueError:
            relative = Path(source.name)
        destination = output_dir / relative
    else:
        destination = source.with_name(f"{source.stem}_scrubbed{source.suffix}")

    return destination if overwrite else unique_output_path(destination)


def iter_supported_files(path: Path, recursive: bool) -> Iterable[Path]:
    """Yield one file or all supported files in a folder."""

    if path.is_file():
        if path.suffix.lower() in SUPPORTED_EXTENSIONS or detect_kind(path) != "unknown":
            yield path
        return

    pattern = "**/*" if recursive else "*"
    for child in path.glob(pattern):
        if not child.is_file():
            continue
        if child.suffix.lower() in SUPPORTED_EXTENSIONS or detect_kind(child) != "unknown":
            yield child


def write_json_report(path: Path, reports: list[FileReport]) -> None:
    """Save a machine-readable report for later auditing."""

    path.parent.mkdir(parents=True, exist_ok=True)
    payload = [asdict(report) for report in reports]
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def render_metadata_preview(metadata: dict[str, str], limit: int = 5) -> str:
    """Show a compact sample of metadata fields in the terminal table."""

    private_items = [
        (key, value)
        for key, value in metadata.items()
        if not is_generated_ffmpeg_field(key, value)
    ]
    if not private_items:
        return "No metadata found"

    items = private_items[:limit]
    preview = ", ".join(f"{key}={value}" for key, value in items)
    remaining = len(private_items) - len(items)
    if remaining > 0:
        preview += f", +{remaining} more"
    return preview


def print_reports_table(title: str, reports: list[FileReport]) -> None:
    """Render a readable table for scan and scrub results."""

    table = Table(title=title, show_lines=True)
    table.add_column("File", overflow="fold")
    table.add_column("Kind")
    table.add_column("Action")
    table.add_column("Before")
    table.add_column("After")
    table.add_column("Output", overflow="fold")
    table.add_column("Status")

    for report in reports:
        after = (
            str(report.metadata_after_count)
            if report.metadata_after_count is not None
            else "-"
        )
        table.add_row(
            report.source,
            report.kind,
            report.action,
            str(report.metadata_before_count),
            after,
            report.output or "-",
            report.status if not report.error else f"{report.status}: {report.error}",
        )

    console.print(table)


def print_key_value_table(title: str, values: dict[str, str]) -> None:
    """Render a compact key/value detail table."""

    table = Table(title=title, show_lines=False)
    table.add_column("Field", style="cyan", overflow="fold")
    table.add_column("Value", overflow="fold")

    if not values:
        table.add_row("-", "No fields found")
    else:
        for key, value in values.items():
            table.add_row(key, value)

    console.print(table)


def print_report_details(report: FileReport) -> None:
    """Print full details for a report entry."""

    console.print(Panel.fit(report.source, title=f"{report.kind.title()} Details"))
    technical_title = "Technical Details Before" if report.output else "Technical Details"
    metadata_title = (
        "Private / Scrubbable Metadata Before"
        if report.output
        else "Private / Scrubbable Metadata"
    )
    print_key_value_table(technical_title, report.technical_before)
    print_key_value_table(metadata_title, report.metadata_before)

    if report.output:
        console.print(Panel.fit(report.output, title="Output File"))
        if report.technical_after or report.metadata_after:
            print_key_value_table("Technical Details After", report.technical_after)
            print_key_value_table("Private / Scrubbable Metadata After", report.metadata_after)


def command_inspect(args: argparse.Namespace) -> int:
    """Inspect files and show metadata that could reveal private information."""

    input_path = resolve_input_path(args.path, "inspect", args.recursive)
    if not input_path:
        return 1

    files = list(iter_supported_files(input_path, args.recursive))
    if not files:
        console.print("[yellow]No supported image, audio, or video files found.[/yellow]")
        return 1

    reports: list[FileReport] = []
    for file_path in files:
        try:
            kind, metadata, technical_details = inspect_file(file_path)
            status = render_metadata_preview(metadata)
            if not metadata:
                status = "No private metadata found; see technical details"
            reports.append(
                FileReport(
                    source=str(file_path),
                    kind=kind,
                    action="inspect",
                    status=status,
                    metadata_before_count=len(metadata),
                    metadata_before=metadata,
                    technical_before=technical_details,
                )
            )
        except Exception as exc:
            reports.append(
                FileReport(
                    source=str(file_path),
                    kind=detect_kind(file_path),
                    action="inspect",
                    status="failed",
                    metadata_before_count=0,
                    error=str(exc),
                )
            )

    print_reports_table("Metadata Inspection", reports)

    if args.details:
        for report in reports:
            print_report_details(report)

    if args.report:
        write_json_report(args.report.resolve(), reports)
        console.print(f"[green]Report saved to {args.report.resolve()}[/green]")

    return 0 if all(report.status != "failed" for report in reports) else 2


def command_scrub(args: argparse.Namespace) -> int:
    """Scrub metadata from one file or a batch of files."""

    input_path = resolve_input_path(args.path, "scrub", args.recursive)
    if not input_path:
        return 1

    if args.output and input_path.is_dir():
        console.print("[red]--output can only be used with one input file.[/red]")
        return 1

    files = list(iter_supported_files(input_path, args.recursive))
    if not files:
        console.print("[yellow]No supported image, audio, or video files found.[/yellow]")
        return 1

    input_root = input_path if input_path.is_dir() else input_path.parent
    output_dir = args.output_dir.resolve() if args.output_dir else None
    explicit_output = args.output.resolve() if args.output else None
    reports: list[FileReport] = []

    for file_path in files:
        try:
            kind, metadata_before, technical_before = inspect_file(file_path)
            output_path = choose_output_path(
                source=file_path,
                input_root=input_root,
                explicit_output=explicit_output,
                output_dir=output_dir,
                overwrite=args.overwrite,
            )
            if output_path.resolve() == file_path.resolve():
                raise RuntimeError("Output path cannot be the same as the input file")

            if args.dry_run:
                reports.append(
                    FileReport(
                        source=str(file_path),
                        kind=kind,
                        action="dry-run",
                        status="would scrub",
                        metadata_before_count=len(metadata_before),
                        output=str(output_path),
                        metadata_before=metadata_before,
                        technical_before=technical_before,
                    )
                )
                continue

            if kind == "image":
                scrub_image(file_path, output_path)
            elif kind in {"audio", "video"}:
                scrub_media(
                    source=file_path,
                    output=output_path,
                    kind=kind,
                    overwrite=args.overwrite,
                    drop_subtitles=args.drop_subtitles,
                )
            else:
                raise RuntimeError("Unsupported file type")

            metadata_after: dict[str, str] = {}
            technical_after: dict[str, str] = {}
            after_count: int | None = None
            if args.verify:
                _, metadata_after, technical_after = inspect_file(output_path)
                after_count = len(metadata_after)

            status = "scrubbed"
            if after_count is not None:
                removed_count = max(len(metadata_before) - after_count, 0)
                status = f"scrubbed; removed {removed_count} field(s)"
                if after_count:
                    status += f"; {after_count} remain"

            reports.append(
                FileReport(
                    source=str(file_path),
                    kind=kind,
                    action="scrub",
                    status=status,
                    metadata_before_count=len(metadata_before),
                    metadata_after_count=after_count,
                    output=str(output_path),
                    metadata_before=metadata_before,
                    metadata_after=metadata_after,
                    technical_before=technical_before,
                    technical_after=technical_after,
                )
            )
        except Exception as exc:
            reports.append(
                FileReport(
                    source=str(file_path),
                    kind=detect_kind(file_path),
                    action="scrub",
                    status="failed",
                    metadata_before_count=0,
                    error=str(exc),
                )
            )

    print_reports_table("Metadata Scrub Results", reports)

    if args.report:
        write_json_report(args.report.resolve(), reports)
        console.print(f"[green]Report saved to {args.report.resolve()}[/green]")

    if args.details:
        for report in reports:
            print_report_details(report)

    failures = [report for report in reports if report.status == "failed"]
    return 2 if failures else 0


def command_verify(args: argparse.Namespace) -> int:
    """Compare metadata in an original file and a scrubbed file."""

    original = args.original.resolve()
    scrubbed = args.scrubbed.resolve()

    original_kind, original_metadata, original_technical = inspect_file(original)
    scrubbed_kind, scrubbed_metadata, scrubbed_technical = inspect_file(scrubbed)

    original_count = len(original_metadata)
    scrubbed_count = len(scrubbed_metadata)
    removed = max(original_count - scrubbed_count, 0)

    reports = [
        FileReport(
            source=str(original),
            kind=original_kind,
            action="original",
            status=render_metadata_preview(original_metadata),
            metadata_before_count=original_count,
            metadata_before=original_metadata,
            technical_before=original_technical,
        ),
        FileReport(
            source=str(scrubbed),
            kind=scrubbed_kind,
            action="scrubbed",
            status=f"{removed} field(s) removed compared with original",
            metadata_before_count=scrubbed_count,
            metadata_before=scrubbed_metadata,
            technical_before=scrubbed_technical,
        ),
    ]

    print_reports_table("Metadata Verification", reports)

    if args.details:
        for report in reports:
            print_report_details(report)

    if args.report:
        write_json_report(args.report.resolve(), reports)
        console.print(f"[green]Report saved to {args.report.resolve()}[/green]")

    return 0


def build_parser() -> argparse.ArgumentParser:
    """Create CLI arguments for the application."""

    parser = argparse.ArgumentParser(
        description="Inspect and scrub useful private metadata from images, audio, and video files."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    inspect_parser = subparsers.add_parser(
        "inspect", help="Show metadata fields found in a file or folder."
    )
    inspect_parser.add_argument(
        "path",
        nargs="?",
        type=Path,
        help="File or folder to inspect. If omitted, a file picker opens.",
    )
    inspect_parser.add_argument(
        "--recursive", action="store_true", help="Scan folders recursively."
    )
    inspect_parser.add_argument(
        "--details", action="store_true", help="Print every metadata field found."
    )
    inspect_parser.add_argument(
        "--report", type=Path, help="Save a JSON report to this path."
    )
    inspect_parser.set_defaults(func=command_inspect)

    scrub_parser = subparsers.add_parser(
        "scrub", help="Remove metadata from a file or supported files in a folder."
    )
    scrub_parser.add_argument(
        "path",
        nargs="?",
        type=Path,
        help="File or folder to scrub. If omitted, a file picker opens.",
    )
    scrub_parser.add_argument(
        "--output", type=Path, help="Output path for one input file."
    )
    scrub_parser.add_argument(
        "--output-dir",
        type=Path,
        help="Folder for scrubbed batch output. Defaults to *_scrubbed beside one file.",
    )
    scrub_parser.add_argument(
        "--recursive", action="store_true", help="Scrub folders recursively."
    )
    scrub_parser.add_argument(
        "--overwrite", action="store_true", help="Allow replacing output files."
    )
    scrub_parser.add_argument(
        "--dry-run", action="store_true", help="Preview what would be scrubbed."
    )
    scrub_parser.add_argument(
        "--verify",
        dest="verify",
        action="store_true",
        default=True,
        help="Inspect output files after scrubbing. This is enabled by default.",
    )
    scrub_parser.add_argument(
        "--no-verify",
        dest="verify",
        action="store_false",
        help="Skip after-scrub verification.",
    )
    scrub_parser.add_argument(
        "--details",
        action="store_true",
        help="Print technical details and private metadata before and after.",
    )
    scrub_parser.add_argument(
        "--drop-subtitles",
        action="store_true",
        help="Drop subtitle streams from video output.",
    )
    scrub_parser.add_argument(
        "--report", type=Path, help="Save a JSON report to this path."
    )
    scrub_parser.set_defaults(func=command_scrub)

    verify_parser = subparsers.add_parser(
        "verify", help="Compare an original file with its scrubbed version."
    )
    verify_parser.add_argument("original", type=Path, help="Original file.")
    verify_parser.add_argument("scrubbed", type=Path, help="Scrubbed file.")
    verify_parser.add_argument(
        "--details", action="store_true", help="Print remaining scrubbed metadata."
    )
    verify_parser.add_argument(
        "--report", type=Path, help="Save a JSON report to this path."
    )
    verify_parser.set_defaults(func=command_verify)

    return parser


def main() -> int:
    """Program entry point."""

    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled by user.[/yellow]")
        raise SystemExit(130)

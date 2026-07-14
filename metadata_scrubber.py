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


def inspect_metadata(path: Path) -> tuple[str, dict[str, str]]:
    """Return the detected file kind and metadata fields."""

    kind = detect_kind(path)
    if kind == "image":
        return kind, inspect_image_metadata(path)
    if kind in {"audio", "video"}:
        return kind, inspect_media_metadata(path)
    return kind, {}


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


def command_inspect(args: argparse.Namespace) -> int:
    """Inspect files and show metadata that could reveal private information."""

    input_path = args.path.resolve()
    files = list(iter_supported_files(input_path, args.recursive))
    if not files:
        console.print("[yellow]No supported image, audio, or video files found.[/yellow]")
        return 1

    reports: list[FileReport] = []
    for file_path in files:
        try:
            kind, metadata = inspect_metadata(file_path)
            reports.append(
                FileReport(
                    source=str(file_path),
                    kind=kind,
                    action="inspect",
                    status=render_metadata_preview(metadata),
                    metadata_before_count=filtered_metadata_count(metadata),
                    metadata_before=metadata,
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
            if not report.metadata_before:
                continue
            console.print(Panel.fit(report.source, title="Details"))
            for key, value in report.metadata_before.items():
                console.print(f"[cyan]{key}[/cyan]: {value}")

    if args.report:
        write_json_report(args.report.resolve(), reports)
        console.print(f"[green]Report saved to {args.report.resolve()}[/green]")

    return 0 if all(report.status != "failed" for report in reports) else 2


def command_scrub(args: argparse.Namespace) -> int:
    """Scrub metadata from one file or a batch of files."""

    input_path = args.path.resolve()
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
            kind, metadata_before = inspect_metadata(file_path)
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
                        metadata_before_count=filtered_metadata_count(metadata_before),
                        output=str(output_path),
                        metadata_before=metadata_before,
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
            after_count: int | None = None
            if args.verify:
                _, metadata_after = inspect_metadata(output_path)
                after_count = filtered_metadata_count(metadata_after)

            status = "scrubbed"
            if after_count:
                status = f"scrubbed, verify found {after_count} field(s)"

            reports.append(
                FileReport(
                    source=str(file_path),
                    kind=kind,
                    action="scrub",
                    status=status,
                    metadata_before_count=filtered_metadata_count(metadata_before),
                    metadata_after_count=after_count,
                    output=str(output_path),
                    metadata_before=metadata_before,
                    metadata_after=metadata_after,
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

    failures = [report for report in reports if report.status == "failed"]
    return 2 if failures else 0


def command_verify(args: argparse.Namespace) -> int:
    """Compare metadata in an original file and a scrubbed file."""

    original = args.original.resolve()
    scrubbed = args.scrubbed.resolve()

    original_kind, original_metadata = inspect_metadata(original)
    scrubbed_kind, scrubbed_metadata = inspect_metadata(scrubbed)

    original_count = filtered_metadata_count(original_metadata)
    scrubbed_count = filtered_metadata_count(scrubbed_metadata)
    removed = max(original_count - scrubbed_count, 0)

    reports = [
        FileReport(
            source=str(original),
            kind=original_kind,
            action="original",
            status=render_metadata_preview(original_metadata),
            metadata_before_count=original_count,
            metadata_before=original_metadata,
        ),
        FileReport(
            source=str(scrubbed),
            kind=scrubbed_kind,
            action="scrubbed",
            status=f"{removed} field(s) removed compared with original",
            metadata_before_count=scrubbed_count,
            metadata_before=scrubbed_metadata,
        ),
    ]

    print_reports_table("Metadata Verification", reports)

    remaining_fields = [
        (key, value)
        for key, value in scrubbed_metadata.items()
        if not is_generated_ffmpeg_field(key, value)
    ]
    if args.details and remaining_fields:
        console.print(Panel.fit(str(scrubbed), title="Remaining Fields"))
        for key, value in remaining_fields:
            console.print(f"[cyan]{key}[/cyan]: {value}")

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
    inspect_parser.add_argument("path", type=Path, help="File or folder to inspect.")
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
    scrub_parser.add_argument("path", type=Path, help="File or folder to scrub.")
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
        "--verify", action="store_true", help="Inspect output files after scrubbing."
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

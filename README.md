<!--
#######################################################################
# Author: Lehlohonolo Adolf Matobakele  
# Email: lehlohonolo.matobakele@gov.ls
# Contacxt: 00266 62320704
#######################################################################
-->

# Metadata Scrubber Tool

A Python command-line privacy tool that inspects and scrubs useful metadata from image, audio, and video files before you share them.

The app can remove common fields such as GPS coordinates, camera/device data, timestamps, creator names, software traces, title/artist/album tags, comments, embedded cover art, chapters, and container metadata.

## Features

- Inspect images, audio files, and video files for metadata.
- Scrub images by re-saving pixels without EXIF, GPS, ICC, or text chunks.
- Scrub audio and video with FFmpeg stream-copy mode so quality is preserved.
- Dry-run mode to preview what would be removed.
- Verification mode to compare before and after metadata counts.
- Batch mode for folders, with optional recursive scanning.
- JSON reports for audit logs.
- File signature detection plus extension matching.

## Supported Files

Images: `.jpg`, `.jpeg`, `.png`, `.webp`, `.tif`, `.tiff`, `.bmp`

Audio: `.mp3`, `.m4a`, `.aac`, `.flac`, `.ogg`, `.opus`, `.wav`, `.wma`

Video: `.mp4`, `.mov`, `.mkv`, `.webm`, `.avi`, `.m4v`

## Install

```powershell
python -m pip install -r requirements.txt
```

## Usage

Inspect one file:

```powershell
python .\metadata_scrubber.py inspect .\photo.jpg --details
```

Preview a scrub without writing output:

```powershell
python .\metadata_scrubber.py scrub .\photo.jpg --dry-run
```

Scrub one file and verify the result:

```powershell
python .\metadata_scrubber.py scrub .\photo.jpg --verify
```

Scrub a video to a specific output path:

```powershell
python .\metadata_scrubber.py scrub .\video.mp4 --output .\video_clean.mp4 --verify
```

Scrub a folder recursively:

```powershell
python .\metadata_scrubber.py scrub .\media_folder --recursive --output-dir .\scrubbed --verify
```

Save an audit report:

```powershell
python .\metadata_scrubber.py scrub .\media_folder --recursive --output-dir .\scrubbed --verify --report .\scrub_report.json
```

Compare an original file with a scrubbed file:

```powershell
python .\metadata_scrubber.py verify .\photo.jpg .\photo_scrubbed.jpg --details
```

## Notes

This tool removes common privacy metadata, but no scrubber can guarantee that every trace is removed from every proprietary format. For highly sensitive releases, inspect the output with more than one tool and consider re-encoding media when stream-copy output is not enough.

Only scrub files you own or are authorized to process.

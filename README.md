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
- Verification runs by default after scrubbing and compares before/after metadata counts.
- Detailed reports split private/scrubbable metadata from normal technical file details.
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

Inspect one file with the file picker:

```powershell
python .\metadata_scrubber.py inspect --details
```

Preview a scrub without writing output. The app will prompt you to select the file:

```powershell
python .\metadata_scrubber.py scrub --dry-run
```

Scrub one selected file and verify the result:

```powershell
python .\metadata_scrubber.py scrub
```

Scrub one selected file and show full details:

```powershell
python .\metadata_scrubber.py scrub --details
```

You can still pass a path manually when you want:

```powershell
python .\metadata_scrubber.py scrub .\video.mp4 --output .\video_clean.mp4 --details
```

Scrub a selected folder recursively. With `--recursive`, the app opens a folder picker:

```powershell
python .\metadata_scrubber.py scrub --recursive --output-dir .\scrubbed --details
```

Save an audit report:

```powershell
python .\metadata_scrubber.py scrub --recursive --output-dir .\scrubbed --details --report .\scrub_report.json
```

Compare an original file with a scrubbed file:

```powershell
python .\metadata_scrubber.py verify .\photo.jpg .\photo_scrubbed.jpg --details
```

## Notes

This tool removes common privacy metadata, but no scrubber can guarantee that every trace is removed from every proprietary format. For highly sensitive releases, inspect the output with more than one tool and consider re-encoding media when stream-copy output is not enough.

Only scrub files you own or are authorized to process.

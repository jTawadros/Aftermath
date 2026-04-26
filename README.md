# Aftermath
Aftermath is a CLI tool (to be expanded to a gui interface) for triaging **KAPE output folders**.
It validates the input, performs a basic inventory scan, and can export a “triaged” view of the artifacts into organized folders
(hives, prefetch, shortcuts, databases, etc.). 
During export it generates a `manifest.jsonl` that includes a SHA-256 hash per artifact for file integrity verification.

## Structure
- 'aftermath/cli.py'
    CLI entrypoint (parser, args, etc)

- 'aftermath/dir_ingest.py'
    Input validation + heuristic check e.g. "Is this KAPE output?"

- 'aftermath/scan.py'
    Inventory scan (file counts, bytes, extension) READ-ONLY

- 'aftermath/triage_export.py'
    Artifact classification + export into bucketed folders + SHA-256 manifest

- 'aftermath/formatted_prints.py'
    Formatted Printing for an easy understanding from the console.

- 'aftermath/artifact_rules.py'
    Rule set filled with dictionaries containing naming conventions, file extensions, and export path.

- 'aftermath/manifest_query.py'
    Loads and searches manifest.jsonl records.

- 'aftermath/sensitivity.py'
    Generates sensitivity and priority reports from manifest records.

- 'aftermath/verify.py'
    Recomputes SHA-256 hashes for copied artifacts and verifies them against the manifest.

- 'app.py'
    PySide6 desktop GUI prototype.

- 'run_ui.sh'
    Convenience launcher for the PySide6 GUI.


## Requirements
- Python 3.12+

## Usage
```bash
python3 -m aftermath.cli -i /path/to/KAPE_output -o /path/to/triaged_output
```

## CLI Modes

Aftermath has two main CLI workflows:

1. **Triage mode** - takes a KAPE output folder and creates a triaged output folder.
2. **Manifest mode** - reads an existing `manifest.jsonl` and performs searches, reports, or integrity checks.

### Triage Mode

Triage mode uses `--input` / `-i` and optionally `--output` / `-o`.

```bash
python3 -m aftermath.cli -i /path/to/KAPE_output -o /path/to/triaged_output
```

If you do not provide an ouput path, Aftermath will create a triaged folder automatically.

```bash
python3 -m aftermath.cli -i /path/to/KAPE_output
```

### Manifest Mode
Manifest mode, '--manifest', allows you to query/analyze the previously generated manifest.

```bash
python3 -m aftermath.cli --manifest /path/to/triaged_output/manifest.jsonl
```

Manifest mode supports:

- artifact search
- sensitivity reporting
- filtering by sensitivity level
- integrity verification

## Output
This command, when given a valid KAPE output as input will generate an output
directory with bucket folders such as
- hives/

- prefetch/

- shortcuts/

- databases/

- other/

### Bucket Folders
Artifacts are copied into bucket folders for fast access. Filenames are flattened within each bucket.
If two files share the same name, collision handling is applied.
For example,
- file.ext
- file_2.ext
- file_3.ext

### Manifest

A manifest.jsonl is generated in the new output directory. Each line is a JSON object containing:
- bucket
- relative_source (path relative to the KAPE input root)
- src (absolute source path)
- relative_destination (relative path to the triaged output root)
- size (bytes)
- sha256 (SHA-256 hash of the source artifact)

The manifest is meant to provide a bit of traceability to the original KAPE capture
in addition to allowing integrity verification of the triaged copy.

## Manifest Query Examples

Aftermath can search a generated `manifest.jsonl` without rerunning triage.

### Search by Bucket

```bash
python3 -m aftermath.cli \
  --manifest /path/to/triaged_output/manifest.jsonl \
  --bucket databases
```

### Search by Exact Filename

```bash
python3 -m aftermath.cli \
  --manifest /path/to/triaged_output/manifest.jsonl \
  --name History
```

### Search by Substring

The `--contains` option searches across the source path, destination path, bucket, and stored source fields.

```bash
python3 -m aftermath.cli \
  --manifest /path/to/triaged_output/manifest.jsonl \
  --contains chrome
```

Other examples:

```bash
python3 -m aftermath.cli --manifest /path/to/manifest.jsonl --contains password
python3 -m aftermath.cli --manifest /path/to/manifest.jsonl --contains log --limit 5
python3 -m aftermath.cli --manifest /path/to/manifest.jsonl --contains history
```

### Search by SHA-256

```bash
python3 -m aftermath.cli \
  --manifest /path/to/triaged_output/manifest.jsonl \
  --sha256 <hash>
```

### Search by File Size

```bash
python3 -m aftermath.cli \
  --manifest /path/to/triaged_output/manifest.jsonl \
  --min-size 1000000
```

```bash
python3 -m aftermath.cli \
  --manifest /path/to/triaged_output/manifest.jsonl \
  --max-size 500000
```

### Limit Results

```bash
python3 -m aftermath.cli \
  --manifest /path/to/triaged_output/manifest.jsonl \
  --contains log \
  --limit 10
```

## Sensitivity / Priority Report

Aftermath generates a sensitivity report from your existing `manifest.jsonl`.

```bash
python3 -m aftermath.cli \
  --manifest /path/to/triaged_output/manifest.jsonl \
  --sensitivity
```

The sensitivity report highlights artifacts that may be high-value during forensic review.

Examples include:

- registry hives
- registry exports
- databases
- event logs
- browser-related artifacts
- possible credential or secret artifacts
- possible email artifacts

Sensitivity levels are currently:

- `HIGH`
- `MEDIUM`
- `LOW`

The current report is heuristic-based. It uses bucket names, filenames, and path indicators to flag likely high-value artifacts. It does not currently parse file contents or extract credentials from inside files.
**file parsing for even more detailed sensitivity reports is a planned feature**

### Show Artifacts by Sensitivity Level

```bash
python3 -m aftermath.cli \
  --manifest /path/to/triaged_output/manifest.jsonl \
  --show-sensitive HIGH
```

```bash
python3 -m aftermath.cli \
  --manifest /path/to/triaged_output/manifest.jsonl \
  --show-sensitive MEDIUM \
  --limit 10
```

## Integrity Verification

Using the sha256 hashes, Aftermath can verify that copied triage artifiacts still match the original hashes stored in the manifest.

```bash
python3 -m aftermath.cli \
  --manifest /path/to/triaged_output/manifest.jsonl \
  --verify-integrity
```

This recomputes the SHA-256 hash of each copied artifact and compares it against the hash stored in `manifest.jsonl`.

The integrity check reports:

- missing files
- hash mismatches
- successful verification when all files match

## Running the GUI

Aftermath includes a PySide6 desktop GUI prototype.

The GUI wraps the main workflows into tabs:

- Triage
- Manifest Search
- Sensitivity Report
- Integrity Check

Run the GUI with:

```bash
./run_ui.sh
```

If running manually from WSL, this may be required:

```bash
source .venv/bin/activate
QT_QPA_PLATFORM=xcb python app.py
```

The GUI is currently a prototype wrapper around the existing CLI logic.

## Tech Stack
### Core Language
- **Python 3**
- **PySide6** - Desktop GUI framework
- **collections.Counter** - Counting sensitivity levels and byte totals.
### Key Libraries
- **argparse** - CLI for running the triage tool.
- **pathlib** - Cross-platform filesystem navigation and path handling.
- **hashlib** - SHA256 hashing to verify artifact integrity.
- **json** - Creation of manifest.json.
- **shutil** - File copying during export.

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


## Requirements
- Python 3.12+

## Usage
```bash
python3 -m aftermath.cli -i /path/to/KAPE_output -o /path/to/triaged_output
```

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

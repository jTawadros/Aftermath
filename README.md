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

import argparse
import pathlib
from aftermath.dir_ingest import is_valid_dir
from aftermath.scan import scan_folders
from aftermath.triage_export import classify_file, export_triaged


def build_parser():
    parser = argparse.ArgumentParser(
        prog="aftermath",
        description='Triages Kape output'
    )

    # Input required to specify the KAPE folder
    parser.add_argument('-i',
                        '--input',
                        required=True,
                        help="Path to KAPE output directory")

    # Output not required (default will be inside the KAPE output folder)
    parser.add_argument("-o",
                        "--output",
                        required=False,
                        help="Output directory for triaged files")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    in_path = pathlib.Path(args.input).expanduser().resolve()

    print(f"Validating Path: {in_path}")
    validated_path = is_valid_dir(in_path)
    if validated_path is None:
        return 1

    if args.output:
        triaged_root = pathlib.Path(args.output).expanduser().resolve()
    else:
        triaged_root = pathlib.Path.cwd() / f"triaged_{validated_path.name}"

    bucket_counts = export_triaged(validated_path, triaged_root)

    results = scan_folders(validated_path)
    print(results)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

import argparse
import pathlib
from aftermath.dir_ingest import is_valid_dir


def build_parser():
    parser = argparse.ArgumentParser(
        prog="aftermath",
        description='Triages Kape output'
    )

    parser.add_argument('-i',
                        '--input',
                        required=True,
                        help="Path to KAPE output directory")
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    in_path = pathlib.Path(args.input).expanduser().resolve()

    print(f"Validating Path: {in_path}")
    validated_path = is_valid_dir(in_path)
    if validated_path is None:
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

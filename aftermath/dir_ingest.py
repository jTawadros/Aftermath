from pathlib import Path


def is_valid_dir(path: Path) -> Path | None:
    if not path.exists():
        print("Path does not exist.")
        return None
    if path.is_dir():
        print("Path exists...")
        print("Validating with KAPE")
        is_valid_kape = is_valid_kape_output(path)
        if is_valid_kape:
            print("Confirmed KAPE heuristics")
            return path
        else:
            print("Not valid KAPE")
            return None
    print("Unsupported input.")
    return None


def is_valid_kape_output(path: Path) -> bool:
    pattern = "*ConsoleLog*"
    if any(path.glob(pattern)):
        for p in path.glob("*ConsoleLog*"):
            print(p, type(p))
        return True

    return False

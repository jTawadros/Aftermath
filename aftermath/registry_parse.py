# aftermath/registry_parse.py

from pathlib import Path
from Registry import Registry


INTERESTING_KEYS = {
    "SOFTWARE": [
        r"Microsoft\Windows\CurrentVersion\Run",
        r"Microsoft\Windows\CurrentVersion\RunOnce",
        r"Microsoft\Windows NT\CurrentVersion",
        r"Microsoft\Windows\CurrentVersion\Uninstall",
    ],
    "SYSTEM": [
        r"Select",
        r"CurrentControlSet\Control\ComputerName\ComputerName",
        r"CurrentControlSet\Control\TimeZoneInformation",
        r"CurrentControlSet\Services",
        r"CurrentControlSet\Enum\USBSTOR",
        r"CurrentControlSet\Enum\USB",
        r"CurrentControlSet\Control\Session Manager\Environment",
    ],
    "NTUSER.DAT": [
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
        r"Software\Microsoft\Internet Explorer\TypedURLs",
    ],
}

def guess_hive_type(path: Path) -> str:
    name = path.name.upper()

    if name in {"SYSTEM", "SOFTWARE", "SAM", "SECURITY"}:
        return name

    if name == "NTUSER.DAT":
        return "NTUSER.DAT"

    if name == "USRCLASS.DAT":
        return "USRCLASS.DAT"

    return "UNKNOWN"


def value_to_string(value) -> str:
    try:
        data = value.value()
    except Exception:
        return "<unable to read value>"

    if isinstance(data, bytes):
        return data.hex()

    return str(data)


def parse_key(registry, key_path: str) -> list[str]:
    lines = []

    try:
        key = registry.open(key_path)
    except Exception:
        return lines

    lines.append(f"[KEY] {key_path}")
    lines.append(f"Last Written: {key.timestamp()}")

    try:
        values = key.values()
    except Exception:
        values = []

    if not values:
        lines.append("  (no values)")

    for value in values:
        try:
            value_name = value.name() or "(Default)"
            value_type = value.value_type_str()
            value_data = value_to_string(value)
            lines.append(f"  {value_name} [{value_type}] = {value_data}")
        except Exception as e:
            lines.append(f"  <error reading value: {e}>")

    lines.append("")
    return lines


def parse_registry_hive(hive_path: Path) -> str:
    hive_path = Path(hive_path)
    hive_type = guess_hive_type(hive_path)

    lines = []
    lines.append("===== REGISTRY HIVE REPORT =====")
    lines.append(f"Hive Path : {hive_path}")
    lines.append(f"Hive Type : {hive_type}")
    lines.append("")

    if hive_type not in INTERESTING_KEYS:
        lines.append("No parser rules available for this hive type yet.")
        return "\n".join(lines)

    try:
        registry = Registry.Registry(str(hive_path))
    except Exception as e:
        lines.append(f"Failed to open hive: {e}")
        return "\n".join(lines)

    key_paths = list(INTERESTING_KEYS[hive_type])

    if hive_type == "SYSTEM":
        current_control_set = get_current_control_set(registry)

        if current_control_set:
            expanded = []
            for key_path in key_paths:
                expanded.append(key_path)

                if key_path.startswith("CurrentControlSet\\"):
                    expanded.append(
                        key_path.replace("CurrentControlSet", current_control_set, 1)
                    )

            key_paths = expanded
            lines.append(f"Resolved CurrentControlSet: {current_control_set}")
            lines.append("")

    for key_path in key_paths:
        lines.extend(parse_key(registry, key_path))

    return "\n".join(lines)


def parse_registry_hives_from_triage(triaged_root: Path) -> dict[str, str]:
    triaged_root = Path(triaged_root)

    hive_candidates = []

    for folder in [
        triaged_root / "hives" / "system" / "core",
        triaged_root / "hives" / "user" / "core",
    ]:
        if folder.exists():
            for p in folder.iterdir():
                if p.is_file():
                    hive_candidates.append(p)

    reports = {}

    for hive_path in hive_candidates:
        report = parse_registry_hive(hive_path)
        reports[str(hive_path)] = report

    return reports

def get_current_control_set(registry) -> str | None:
    try:
        select_key = registry.open("Select")
        current_value = select_key.value("Current").value()
        return f"ControlSet{int(current_value):03d}"
    except Exception:
        return None


def summarize_registry_findings(registry_findings: dict[str, str]) -> list[str]:
    summary = []

    for path, report in registry_findings.items():
        path_lower = path.lower()
        report_lines = report.splitlines()
        if path_lower.endswith("software"):
            os_name = None
            service_pack = None
            registered_owner = None
            startup_entries = []

            for line in report_lines:
                stripped = line.strip()

                if stripped.startswith("ProductName "):
                    os_name = stripped.split("=", 1)[1].strip()

                elif stripped.startswith("CSDVersion "):
                    service_pack = stripped.split("=", 1)[1].strip()

                elif stripped.startswith("RegisteredOwner "):
                    registered_owner = stripped.split("=", 1)[1].strip()

                elif stripped.startswith("VMware") and " [RegSZ] = " in stripped:
                    name = stripped.split("[", 1)[0].strip()
                    value = stripped.split("=", 1)[1].strip()
                    startup_entries.append(f"{name} -> {value}")

            summary.append("[HIGH] SOFTWARE hive")
            summary.append("Why it matters:")
            summary.append("  - Contains operating system version, install metadata, registered owner, and startup program locations.")
            summary.append("Key findings:")

            if os_name:
                summary.append(f"  - OS: {os_name}")

            if service_pack:
                summary.append(f"  - Service pack: {service_pack}")

            if registered_owner:
                summary.append(f"  - Registered owner: {registered_owner}")

            for entry in startup_entries:
                summary.append(f"  - Startup entry: {entry}")

            summary.append("")


        elif path_lower.endswith("system"):
            summary.append("[HIGH] SYSTEM hive")
            summary.append("Why it matters:")
            summary.append("  - Contains host identity, timezone, active control set, services, USB device registry locations, and environment settings.")
            summary.append("Key findings:")

            for line in report_lines:
                stripped = line.strip()

                if stripped.startswith("Resolved CurrentControlSet:"):
                    summary.append(f"  - {stripped}")

                if stripped.startswith("ComputerName "):
                    summary.append(f"  - Hostname: {stripped.split('=', 1)[1].strip()}")

                if stripped.startswith("StandardName "):
                    summary.append(f"  - Timezone: {stripped.split('=', 1)[1].strip()}")

                if stripped.startswith("OS "):
                    summary.append(f"  - OS environment value: {stripped.split('=', 1)[1].strip()}")

                if stripped.startswith("PROCESSOR_ARCHITECTURE "):
                    summary.append(f"  - Processor architecture: {stripped.split('=', 1)[1].strip()}")

            summary.append("")

        elif path_lower.endswith("ntuser.dat"):
            summary.append("[HIGH] NTUSER.DAT hive")
            summary.append("Why it matters:")
            summary.append("  - Contains user-specific activity and persistence locations such as Run keys, RecentDocs, UserAssist, TypedPaths, and TypedURLs when present.")
            summary.append("Key findings:")

            if "(no values)" in report:
                summary.append("  - Parsed user Run key, but no startup values were present in this sample.")
            else:
                summary.append("  - User-specific values were found. Review raw registry details below.")

            summary.append("")

        elif path_lower.endswith("sam"):
            summary.append("[HIGH] SAM hive")
            summary.append("Why it matters:")
            summary.append("  - Contains local account/security metadata. Aftermath detects it as high priority but does not parse SAM internals yet.")
            summary.append("")

        elif path_lower.endswith("security"):
            summary.append("[HIGH] SECURITY hive")
            summary.append("Why it matters:")
            summary.append("  - Contains local security policy and related security metadata. Aftermath detects it as high priority but does not parse SECURITY internals yet.")
            summary.append("")

    if not summary:
        summary.append("No registry summary findings available.")

    return summary

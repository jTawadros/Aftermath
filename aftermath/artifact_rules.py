# artifact_rules.py

SYSTEM_HIVES = {"SYSTEM", "SOFTWARE", "SAM", "SECURITY", "HARDWARE"}
USER_HIVES = {"NTUSER.DAT", "USRCLASS.DAT"}

EXACT_NAME_BUCKETS = {
    "$MFT": "filesystem/ntfs",
    "$BOOT": "filesystem/ntfs",
    "$LOGFILE": "filesystem/ntfs",
    "$SECURE_$SDS": "filesystem/ntfs",

    "DESKTOP.INI": "configs",
    "INFO2": "other/recycle_bin",
}

PREFIX_BUCKETS = {
    "_REGISTRY_MACHINE_": "hives/system/kape_exports",
    "_REGISTRY_USER_NTUSER_": "hives/user/kape_exports",
    "_REGISTRY_USER_USRCLASS_": "hives/user/kape_exports",
    "_REGISTRY_USER__": "hives/user/kape_exports",

    "$MFT": "filesystem/ntfs",
    "$BOOT": "filesystem/ntfs",
    "$LOGFILE": "filesystem/ntfs",
    "$SECURE": "filesystem/ntfs",
}

HIVE_LOG_BUCKETS = {
    "SAM.LOG": "hives/system/logs",
    "SECURITY.LOG": "hives/system/logs",
    "SOFTWARE.LOG": "hives/system/logs",
    "SYSTEM.LOG": "hives/system/logs",
    "DEFAULT.LOG": "hives/user/logs",
}

EXTENSION_BUCKETS = {
    ".pf": "prefetch",
    ".lnk": "shortcuts",

    ".jpg": "pictures",
    ".jpeg": "pictures",
    ".png": "pictures",
    ".gif": "pictures",
    ".bmp": "pictures",
    ".tif": "pictures",
    ".tiff": "pictures",
    ".webp": "pictures",
    ".heic": "pictures",

    ".pdf": "pdfs",

    ".sqlite": "databases",
    ".db": "databases",
    ".sqlite-journal": "databases",

    ".txt": "text_reports",
    ".log": "text_reports",
    ".csv": "text_reports",

    ".evt": "event_logs",
    ".evtx": "event_logs",

    ".ini": "configs",
    ".cfg": "configs",
}

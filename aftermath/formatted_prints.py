def print_filecounts(ext_counts: dict):
    print(" =============== COUNTS AND SIZE =============== ")
    for key, val in ext_counts.items():
        if key != "extension_counts":
            print(f"{key:<16} | {val:>14}")
        else:
            print(" ========== FILE COUNTS BY EXTENSIONS ========== ")
            for k, v in val.items():
                print(f"{k:<16} | {v:>14}")


def print_bucket_counts(bucket_counts: dict):
    print(" ============== TRIAGE BUCKET COUNTS ============= ")
    for bucket, count in sorted(bucket_counts.items()):
        print(f"{bucket:<30} | {count:>10}")

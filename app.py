from pathlib import Path
from aftermath.registry_parse import summarize_registry_findings
import sys

from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QTabWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QLabel,
    QLineEdit,
    QFileDialog,
    QTextEdit,
    QSpinBox,
    QComboBox,
)

from aftermath.dir_ingest import is_valid_kape_output
from aftermath.triage_export import export_triaged
from aftermath.scan import scan_folders
from aftermath.manifest_query import query_manifest, load_manifest
from aftermath.verify import verify_manifest_integrity
from aftermath.sensitivity import (
    generate_sensitivity_report,
    filter_by_sensitivity,
)


def format_bytes(num_bytes: int) -> str:
    size = float(num_bytes)
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} TB"


class AftermathWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Aftermath Forensic Triage")
        self.resize(1000, 700)

        tabs = QTabWidget()
        tabs.addTab(self.build_triage_tab(), "Triage")
        tabs.addTab(self.build_manifest_tab(), "Manifest Search")
        tabs.addTab(self.build_sensitivity_tab(), "Sensitivity Report")
        tabs.addTab(self.build_integrity_tab(), "Integrity Check")

        self.setCentralWidget(tabs)

    def make_path_row(self, label_text, line_edit, browse_callback):
        row = QHBoxLayout()
        row.addWidget(QLabel(label_text))
        row.addWidget(line_edit)

        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(browse_callback)
        row.addWidget(browse_button)

        return row

    def browse_folder(self, line_edit):
        folder = QFileDialog.getExistingDirectory(self, "Select Folder")
        if folder:
            line_edit.setText(folder)

    def browse_file(self, line_edit):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Manifest",
            "",
            "JSONL Files (*.jsonl);;All Files (*)",
        )
        if file_path:
            line_edit.setText(file_path)

    def build_triage_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        self.triage_input = QLineEdit()
        self.triage_output = QLineEdit()
        self.triage_output_box = QTextEdit()
        self.triage_output_box.setReadOnly(True)

        layout.addLayout(
            self.make_path_row(
                "KAPE Output:",
                self.triage_input,
                lambda: self.browse_folder(self.triage_input),
            )
        )

        layout.addLayout(
            self.make_path_row(
                "Triaged Output:",
                self.triage_output,
                lambda: self.browse_folder(self.triage_output),
            )
        )

        run_button = QPushButton("Run Triage")
        run_button.clicked.connect(self.run_triage)

        layout.addWidget(run_button)
        layout.addWidget(self.triage_output_box)

        tab.setLayout(layout)
        return tab

    def run_triage(self):
        self.triage_output_box.clear()

        input_path = Path(self.triage_input.text()).expanduser().resolve()
        output_path = Path(self.triage_output.text()).expanduser().resolve()

        if not input_path.exists() or not input_path.is_dir():
            self.triage_output_box.setText("Input path does not exist or is not a directory.")
            return

        if not is_valid_kape_output(input_path):
            self.triage_output_box.setText("This does not look like valid KAPE output.")
            return

        bucket_counts = export_triaged(input_path, output_path)
        scan_results = scan_folders(input_path)

        lines = []
        lines.append("Triage complete.")
        lines.append("")
        lines.append(f"Manifest: {output_path / 'manifest.jsonl'}")
        lines.append(f"Total files: {scan_results.get('total_files', 0)}")
        lines.append(f"Total size: {format_bytes(scan_results.get('total_bytes', 0))}")
        lines.append("")
        lines.append("Bucket Counts:")

        for bucket, count in sorted(bucket_counts.items()):
            lines.append(f"  {bucket:<30} {count}")

        lines.append("")
        lines.append("Extension Counts:")

        for ext, count in sorted(scan_results.get("extension_counts", {}).items()):
            lines.append(f"  {ext:<12} {count}")

        self.triage_output_box.setText("\n".join(lines))

    def build_manifest_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        self.manifest_path = QLineEdit()
        self.manifest_bucket = QLineEdit()
        self.manifest_name = QLineEdit()
        self.manifest_contains = QLineEdit()
        self.manifest_sha256 = QLineEdit()
        self.manifest_limit = QSpinBox()
        self.manifest_limit.setRange(1, 1000)
        self.manifest_limit.setValue(25)

        self.manifest_output_box = QTextEdit()
        self.manifest_output_box.setReadOnly(True)

        layout.addLayout(
            self.make_path_row(
                "Manifest:",
                self.manifest_path,
                lambda: self.browse_file(self.manifest_path),
            )
        )

        layout.addWidget(QLabel("Bucket:"))
        layout.addWidget(self.manifest_bucket)

        layout.addWidget(QLabel("Exact filename:"))
        layout.addWidget(self.manifest_name)

        layout.addWidget(QLabel("Contains:"))
        layout.addWidget(self.manifest_contains)

        layout.addWidget(QLabel("SHA-256:"))
        layout.addWidget(self.manifest_sha256)

        layout.addWidget(QLabel("Limit:"))
        layout.addWidget(self.manifest_limit)

        search_button = QPushButton("Search Manifest")
        search_button.clicked.connect(self.search_manifest)

        layout.addWidget(search_button)
        layout.addWidget(self.manifest_output_box)

        tab.setLayout(layout)
        return tab

    def search_manifest(self):
        self.manifest_output_box.clear()

        manifest_path = Path(self.manifest_path.text()).expanduser().resolve()

        if not manifest_path.exists():
            self.manifest_output_box.setText("Manifest path does not exist.")
            return

        results = query_manifest(
            manifest_path,
            bucket=self.manifest_bucket.text() or None,
            name=self.manifest_name.text() or None,
            contains=self.manifest_contains.text() or None,
            sha256=self.manifest_sha256.text() or None,
            limit=self.manifest_limit.value(),
        )

        lines = []
        lines.append(f"Found {len(results)} matching record(s).")
        lines.append("")

        for i, record in enumerate(results, start=1):
            lines.append(f"[{i}] bucket: {record.get('bucket', '')}")
            lines.append(f"    relative_source      : {record.get('relative_source', '')}")
            lines.append(f"    relative_destination : {record.get('relative_destination', '')}")
            lines.append(f"    size                 : {record.get('size', '')}")
            lines.append(f"    sha256               : {record.get('sha256', '')}")
            lines.append("")

        self.manifest_output_box.setText("\n".join(lines))

    def build_sensitivity_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        self.sensitivity_manifest_path = QLineEdit()
        self.sensitivity_level = QComboBox()
        self.sensitivity_level.addItems(["All", "HIGH", "MEDIUM", "LOW"])

        self.sensitivity_limit = QSpinBox()
        self.sensitivity_limit.setRange(1, 1000)
        self.sensitivity_limit.setValue(25)

        self.sensitivity_output_box = QTextEdit()
        self.sensitivity_output_box.setReadOnly(True)

        layout.addLayout(
            self.make_path_row(
                "Manifest:",
                self.sensitivity_manifest_path,
                lambda: self.browse_file(self.sensitivity_manifest_path),
            )
        )

        layout.addWidget(QLabel("Sensitivity filter:"))
        layout.addWidget(self.sensitivity_level)

        layout.addWidget(QLabel("Limit:"))
        layout.addWidget(self.sensitivity_limit)

        run_button = QPushButton("Generate Sensitivity Report")
        run_button.clicked.connect(self.run_sensitivity_report)

        layout.addWidget(run_button)
        layout.addWidget(self.sensitivity_output_box)

        tab.setLayout(layout)
        return tab

    def run_sensitivity_report(self):
        self.sensitivity_output_box.clear()

        manifest_path = Path(self.sensitivity_manifest_path.text()).expanduser().resolve()

        if not manifest_path.exists():
            self.sensitivity_output_box.setText("Manifest path does not exist.")
            return

        counts, sizes, flagged, registry_findings = generate_sensitivity_report(manifest_path)

        lines = []
        lines.append("SENSITIVITY / PRIORITY REPORT")
        lines.append("")
        lines.append("Summary:")

        for level in ["HIGH", "MEDIUM", "LOW"]:
            lines.append(
                f"{level:<10} | files: {counts[level]:>6} | bytes: {sizes[level]:>12}"
            )

        lines.append("")

        selected_level = self.sensitivity_level.currentText()

        if selected_level == "All":
            lines.append("Top flagged artifacts:")
            lines.append("")

            selected_items = flagged[:self.sensitivity_limit.value()]

            if not selected_items:
                lines.append("No high or medium priority artifacts were flagged.")

            for i, item in enumerate(selected_items, start=1):
                record = item["record"]

                lines.append(f"[{i}] {item['level']}")
                lines.append(f"    bucket               : {record.get('bucket', '')}")
                lines.append(f"    relative_source      : {record.get('relative_source', '')}")
                lines.append(f"    relative_destination : {record.get('relative_destination', '')}")
                lines.append(f"    size                 : {record.get('size', '')}")
                lines.append(f"    sha256               : {record.get('sha256', '')}")
                lines.append("    reason(s):")

                for reason in item["reasons"]:
                    lines.append(f"      - {reason}")

                lines.append("")
        else:
            records = load_manifest(manifest_path)
            filtered = filter_by_sensitivity(records, selected_level)

            lines.append(f"{selected_level} sensitivity artifacts:")
            lines.append("")

            for i, record in enumerate(filtered[:self.sensitivity_limit.value()], start=1):
                lines.append(f"[{i}] bucket: {record.get('bucket', '')}")
                lines.append(f"    relative_source      : {record.get('relative_source', '')}")
                lines.append(f"    relative_destination : {record.get('relative_destination', '')}")
                lines.append(f"    size                 : {record.get('size', '')}")
                lines.append(f"    sha256               : {record.get('sha256', '')}")
                lines.append("")
                lines.append("")
        lines.append("REGISTRY ANALYST SUMMARY")
        lines.append("")

        if not registry_findings:
            lines.append("No registry hive findings available.")
        else:
            lines.extend(summarize_registry_findings(registry_findings))

            lines.append("")
            lines.append("RAW REGISTRY DETAILS")
            lines.append("")

            for path, report in registry_findings.items():
                lines.append(report)
                lines.append("=" * 80)

        self.sensitivity_output_box.setText("\n".join(lines))


    def build_integrity_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        self.integrity_manifest_path = QLineEdit()
        self.integrity_output_box = QTextEdit()
        self.integrity_output_box.setReadOnly(True)

        layout.addLayout(
            self.make_path_row(
                "Manifest:",
                self.integrity_manifest_path,
                lambda: self.browse_file(self.integrity_manifest_path),
            )
        )

        run_button = QPushButton("Verify Integrity")
        run_button.clicked.connect(self.run_integrity_check)

        layout.addWidget(run_button)
        layout.addWidget(self.integrity_output_box)

        tab.setLayout(layout)
        return tab

    def run_integrity_check(self):
        self.integrity_output_box.clear()

        manifest_path = Path(self.integrity_manifest_path.text()).expanduser().resolve()

        if not manifest_path.exists():
            self.integrity_output_box.setText("Manifest path does not exist.")
            return

        mismatches, missing = verify_manifest_integrity(manifest_path)

        lines = []
        lines.append("INTEGRITY CHECK")
        lines.append("")

        if not mismatches and not missing:
            lines.append("All files verified successfully.")

        if missing:
            lines.append(f"Missing files ({len(missing)}):")
            for f in missing[:25]:
                lines.append(f"  {f}")
            lines.append("")

        if mismatches:
            lines.append(f"Hash mismatches ({len(mismatches)}):")
            for f, expected, actual in mismatches[:25]:
                lines.append(f"  {f}")
                lines.append(f"    expected: {expected}")
                lines.append(f"    actual  : {actual}")
                lines.append("")

        self.integrity_output_box.setText("\n".join(lines))


def main():
    app = QApplication(sys.argv)
    window = AftermathWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()

from __future__ import annotations

import csv
import threading
from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QProgressBar,
    QRadioButton,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from audit.desktop.assessment import AssessmentService


class Signals(QWidget):
    log = Signal(str)
    progress = Signal(int)
    row = Signal(dict)
    done = Signal()


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Email Security Posture Assessment")
        self.resize(1300, 900)

        self.signals = Signals()
        self.assessment_service = AssessmentService()
        self.latest_reports: dict[int, Path] = {}

        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)

        layout.addWidget(self._build_input_section())
        layout.addWidget(self._build_output_section())
        layout.addWidget(self._build_execution_section())
        layout.addWidget(self._build_logs_section())

        self.signals.log.connect(self.append_log)
        self.signals.progress.connect(self.progress.setValue)
        self.signals.row.connect(self.add_result_row)
        self.signals.done.connect(self.on_complete)

        self.update_preview()

    def _build_input_section(self) -> QGroupBox:
        group = QGroupBox("SECTION A – INPUT")
        grid = QGridLayout(group)

        self.single_radio = QRadioButton("Single Domain")
        self.bulk_radio = QRadioButton("Bulk Domains")
        self.single_radio.setChecked(True)
        self.mode_group = QButtonGroup(self)
        self.mode_group.addButton(self.single_radio)
        self.mode_group.addButton(self.bulk_radio)

        self.single_domain = QLineEdit()
        self.single_domain.setPlaceholderText("example.com")
        self.bulk_domains = QPlainTextEdit()
        self.bulk_domains.setPlaceholderText("one domain per line")
        self.bulk_domains.setFixedHeight(100)

        self.import_button = QPushButton("Import TXT/CSV")
        self.import_button.clicked.connect(self.import_domains)

        self.resolve_spf_checkbox = QCheckBox("Resolve SPF includes and redirect")
        self.resolve_spf_checkbox.setChecked(True)
        self.json_checkbox = QCheckBox("Generate JSON output")
        self.json_checkbox.setChecked(True)
        self.pdf_checkbox = QCheckBox("Generate PDF output (optional)")

        self.single_radio.toggled.connect(self.toggle_mode)

        grid.addWidget(self.single_radio, 0, 0)
        grid.addWidget(self.bulk_radio, 0, 1)
        grid.addWidget(QLabel("Single domain"), 1, 0)
        grid.addWidget(self.single_domain, 1, 1, 1, 3)
        grid.addWidget(QLabel("Bulk domains"), 2, 0)
        grid.addWidget(self.bulk_domains, 2, 1, 1, 2)
        grid.addWidget(self.import_button, 2, 3)
        grid.addWidget(self.resolve_spf_checkbox, 3, 0, 1, 2)
        grid.addWidget(self.json_checkbox, 3, 2)
        grid.addWidget(self.pdf_checkbox, 3, 3)

        self.toggle_mode()
        return group

    def _build_output_section(self) -> QGroupBox:
        group = QGroupBox("SECTION B – OUTPUT")
        grid = QGridLayout(group)

        self.output_folder = QLineEdit(str(Path.cwd() / "output"))
        self.output_browse_button = QPushButton("Browse")
        self.output_browse_button.clicked.connect(self.select_output_folder)

        self.format_combo = QComboBox()
        self.format_combo.addItems(["HTML", "JSON", "Both"])

        self.preview_label = QLabel()
        self.preview_label.setStyleSheet("color: #1f4f96; font-weight: 600;")

        self.single_domain.textChanged.connect(self.update_preview)
        self.format_combo.currentTextChanged.connect(self.update_preview)

        grid.addWidget(QLabel("Output folder"), 0, 0)
        grid.addWidget(self.output_folder, 0, 1, 1, 2)
        grid.addWidget(self.output_browse_button, 0, 3)
        grid.addWidget(QLabel("Report format"), 1, 0)
        grid.addWidget(self.format_combo, 1, 1)
        grid.addWidget(QLabel("Role selection view filter"), 1, 2)
        self.role_combo = QComboBox()
        self.role_combo.addItems(["Executive View", "Technical View", "Red Team View", "Blue Team View"])
        self.role_combo.currentTextChanged.connect(self.apply_role_filter)
        grid.addWidget(self.role_combo, 1, 3)
        grid.addWidget(QLabel("Live file-name preview"), 2, 0)
        grid.addWidget(self.preview_label, 2, 1, 1, 3)
        return group

    def _build_execution_section(self) -> QGroupBox:
        group = QGroupBox("SECTION C – EXECUTION")
        vbox = QVBoxLayout(group)

        top_bar = QHBoxLayout()
        self.run_button = QPushButton("Run Assessment")
        self.run_button.clicked.connect(self.run_assessment)
        self.progress = QProgressBar()
        self.progress.setValue(0)
        self.compare_button = QPushButton("Comparison Mode: Rank Domains")
        self.compare_button.clicked.connect(self.populate_ranking)
        top_bar.addWidget(self.run_button)
        top_bar.addWidget(self.compare_button)
        top_bar.addWidget(self.progress)

        self.results = QTableWidget(0, 8)
        self.results.setHorizontalHeaderLabels(
            ["Domain", "Score", "Tier", "SPF", "DKIM", "DMARC", "Status", "Open Report"]
        )
        self.results.horizontalHeader().setStretchLastSection(True)

        self.ranking = QTableWidget(0, 3)
        self.ranking.setHorizontalHeaderLabels(["Rank", "Domain", "Score"])
        self.ranking.horizontalHeader().setStretchLastSection(True)

        vbox.addLayout(top_bar)
        vbox.addWidget(QLabel("Score Ranking Table"))
        vbox.addWidget(self.ranking)
        vbox.addWidget(QLabel("Assessment Results"))
        vbox.addWidget(self.results)
        return group

    def _build_logs_section(self) -> QGroupBox:
        group = QGroupBox("SECTION D – LOGS")
        vbox = QVBoxLayout(group)
        self.logs = QTextEdit()
        self.logs.setReadOnly(True)
        self.logs.setMinimumHeight(160)
        vbox.addWidget(self.logs)
        return group

    def toggle_mode(self) -> None:
        single = self.single_radio.isChecked()
        self.single_domain.setEnabled(single)
        self.bulk_domains.setEnabled(not single)
        self.import_button.setEnabled(not single)

    def append_log(self, line: str) -> None:
        self.logs.append(line)

    def update_preview(self) -> None:
        domain = self.single_domain.text().strip().lower() or "example.com"
        self.preview_label.setText(AssessmentService.safe_report_filename(domain, "html"))

    def select_output_folder(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Select output folder", self.output_folder.text())
        if folder:
            self.output_folder.setText(folder)

    def import_domains(self) -> None:
        file_path, _ = QFileDialog.getOpenFileName(self, "Import domain file", "", "TXT/CSV (*.txt *.csv)")
        if not file_path:
            return
        path = Path(file_path)
        domains: list[str] = []
        if path.suffix.lower() == ".csv":
            with path.open("r", encoding="utf-8") as f:
                reader = csv.reader(f)
                for row in reader:
                    if row and row[0].strip():
                        domains.append(row[0].strip())
        else:
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.strip() and not line.strip().startswith("#"):
                    domains.append(line.strip())
        self.bulk_domains.setPlainText("\n".join(domains))

    def get_domains(self) -> list[str]:
        if self.single_radio.isChecked():
            raw = [self.single_domain.text().strip()]
        else:
            raw = [line.strip() for line in self.bulk_domains.toPlainText().splitlines()]
        domains = [d for d in raw if d]
        deduped: list[str] = []
        seen: set[str] = set()
        for d in domains:
            normalized = AssessmentService.normalize_domain(d)
            if normalized not in seen:
                deduped.append(normalized)
                seen.add(normalized)
        return deduped

    def run_assessment(self) -> None:
        domains = self.get_domains()
        if not domains:
            QMessageBox.warning(self, "Missing input", "Please provide at least one domain.")
            return

        self.results.setRowCount(0)
        self.ranking.setRowCount(0)
        self.latest_reports.clear()
        self.progress.setValue(0)
        self.run_button.setEnabled(False)
        output_path = Path(self.output_folder.text().strip() or "output")

        def _task() -> None:
            results = self.assessment_service.run_assessment(
                domains=domains,
                output_dir=output_path,
                output_format=self.format_combo.currentText(),
                resolve_spf_chains=self.resolve_spf_checkbox.isChecked(),
                write_json=self.json_checkbox.isChecked(),
                write_pdf=self.pdf_checkbox.isChecked(),
                log=self.signals.log.emit,
                progress=self.signals.progress.emit,
            )
            for item in results:
                self.signals.row.emit(
                    {
                        "domain": item.domain,
                        "score": item.score,
                        "tier": item.tier,
                        "spf": item.spf_status,
                        "dkim": item.dkim_status,
                        "dmarc": item.dmarc_status,
                        "status": item.status,
                        "report_path": str(item.report_path) if item.report_path else "",
                    }
                )
            self.signals.done.emit()

        threading.Thread(target=_task, daemon=True).start()

    def add_result_row(self, row_data: dict) -> None:
        row = self.results.rowCount()
        self.results.insertRow(row)
        values = [
            row_data["domain"],
            str(row_data["score"]),
            row_data["tier"],
            row_data["spf"],
            row_data["dkim"],
            row_data["dmarc"],
            row_data["status"],
        ]
        for col, value in enumerate(values):
            item = QTableWidgetItem(value)
            item.setFlags(item.flags() ^ Qt.ItemFlag.ItemIsEditable)
            self.results.setItem(row, col, item)

        button = QPushButton("Open")
        report_path = row_data.get("report_path")
        button.setEnabled(bool(report_path))
        if report_path:
            report = Path(report_path)
            self.latest_reports[row] = report
            button.clicked.connect(lambda _, r=row: self.open_report(r))
        self.results.setCellWidget(row, 7, button)

    def populate_ranking(self) -> None:
        rows: list[tuple[str, int]] = []
        for row in range(self.results.rowCount()):
            domain_item = self.results.item(row, 0)
            score_item = self.results.item(row, 1)
            if domain_item and score_item:
                rows.append((domain_item.text(), int(score_item.text())))
        rows.sort(key=lambda item: item[1], reverse=True)

        self.ranking.setRowCount(0)
        for idx, (domain, score) in enumerate(rows, start=1):
            row = self.ranking.rowCount()
            self.ranking.insertRow(row)
            self.ranking.setItem(row, 0, QTableWidgetItem(str(idx)))
            self.ranking.setItem(row, 1, QTableWidgetItem(domain))
            self.ranking.setItem(row, 2, QTableWidgetItem(str(score)))

    def apply_role_filter(self) -> None:
        role = self.role_combo.currentText()
        if role == "Executive View":
            hidden = {3, 4, 5}
        elif role == "Technical View":
            hidden = set()
        elif role == "Red Team View":
            hidden = {4}
        else:  # Blue Team View
            hidden = {7}

        for col in range(self.results.columnCount()):
            self.results.setColumnHidden(col, col in hidden)

    def open_report(self, row: int) -> None:
        path = self.latest_reports.get(row)
        if path and path.exists():
            QDesktopServices.openUrl(path.as_uri())
        else:
            QMessageBox.information(self, "Report unavailable", "Report file not found on disk.")

    def on_complete(self) -> None:
        self.run_button.setEnabled(True)
        self.populate_ranking()
        self.apply_role_filter()
        self.append_log("Assessment run complete.")


def start() -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    window.show()
    app.exec()

import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLineEdit, QTextEdit, QLabel, QFileDialog, QMessageBox, QTabWidget, QSizePolicy, QCheckBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
import os

try:
    from analyzer import CHK
except ImportError:
    print("ERROR: Could not import 'CHK' class from 'analyzer.py'.")
    sys.exit(1)

# --- Worker Threads ---
class PIIAnalysisWorker(QThread):
    analysis_finished = pyqtSignal(list, list)
    analysis_error = pyqtSignal(str)
    def __init__(self, indir, enable_groq_recheck, append_to_files):
        super().__init__()
        self.indir = indir
        self.enable_groq_recheck = enable_groq_recheck
        self.append_to_files = append_to_files
    def run(self):
        try:
            analyzer = CHK()
            results = analyzer.check(self.indir, self.enable_groq_recheck, scrub_files=True, create_backup=True, append_to_files=self.append_to_files)
            if isinstance(results, dict):
                analysis_results = results.get("analysis", [])
                anonymized_data = results.get("anonymized_data", [])
            else:
                analysis_results, anonymized_data = results
            if not isinstance(analysis_results, list):
                analysis_results = [str(analysis_results)]
            if not isinstance(anonymized_data, list):
                anonymized_data = [str(anonymized_data)]
            self.analysis_finished.emit(analysis_results, anonymized_data)
        except Exception as e:
            self.analysis_error.emit(f"An error occurred during text analysis: {e}")

class GitHubAnalysisWorker(QThread):
    github_analysis_finished = pyqtSignal(list, list)
    github_analysis_error = pyqtSignal(str)
    def __init__(self, repo_url, enable_groq_recheck, append_to_files):
        super().__init__()
        self.repo_url = repo_url
        self.enable_groq_recheck = enable_groq_recheck
        self.append_to_files = append_to_files
    def run(self):
        try:
            analyzer = CHK()
            results = analyzer.check(self.repo_url, self.enable_groq_recheck, scrub_files=True, create_backup=True, append_to_files=self.append_to_files)
            if isinstance(results, dict):
                analysis_results = results.get("analysis", [])
                anonymized_data = results.get("anonymized_data", [])
            else:
                analysis_results, anonymized_data = results
            if not isinstance(analysis_results, list):
                analysis_results = [str(analysis_results)]
            if not isinstance(anonymized_data, list):
                anonymized_data = [str(anonymized_data)]
            self.github_analysis_finished.emit(analysis_results, anonymized_data)
        except Exception as e:
            self.github_analysis_error.emit(f"An error occurred during GitHub analysis: {e}")

# --- Main GUI ---
class PIIAnalyzerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PII Analyzer")
        self.setGeometry(100, 100, 1000, 700)
        self.setMinimumSize(800, 600)
        self.current_theme = "dark"
        self.init_ui()
        self.theme_toggle_button.clicked.connect(self.toggle_theme)
        self.apply_theme(self.current_theme)

    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)

        # Top bar with Groq Recheck and Append switch, and theme toggle button
        top_bar_layout = QHBoxLayout()
        group_box = QHBoxLayout()

        # Groq Recheck Checkbox
        self.groq_recheck_checkbox = QCheckBox("Groq Recheck")
        self.groq_recheck_checkbox.setChecked(False)
        self.groq_recheck_checkbox.setObjectName("GroqSwitch")
        group_box.addWidget(self.groq_recheck_checkbox)

        # Append to Files Checkbox (styled as switch)
        self.append_files_switch = QCheckBox("Append to Files")
        self.append_files_switch.setChecked(False)
        self.append_files_switch.setObjectName("AppendSwitch")
        group_box.addWidget(self.append_files_switch)
        group_box.addSpacing(20)

        top_bar_layout.addLayout(group_box)
        top_bar_layout.addStretch(1)

        # Theme toggle button
        self.theme_toggle_button = QPushButton("Toggle Light/Dark Mode")
        self.theme_toggle_button.setFixedWidth(180)
        top_bar_layout.addWidget(self.theme_toggle_button)

        main_layout.addLayout(top_bar_layout)

        # Tabs
        self.tab_widget = QTabWidget()
        self.tab_widget.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        main_layout.addWidget(self.tab_widget)

        # Local Directory Tab
        directory_analysis_tab = QWidget()
        directory_analysis_layout = QVBoxLayout()
        directory_analysis_tab.setLayout(directory_analysis_layout)
        self.tab_widget.addTab(directory_analysis_tab, "Local Directory Analysis")

        # Directory input layout
        dir_input_layout = QHBoxLayout()
        self.dir_label = QLabel("Input Directory:")
        self.dir_label.setFixedWidth(120)
        self.dir_entry = QLineEdit()
        self.dir_entry.setPlaceholderText("Enter path or browse for a directory")
        self.browse_button = QPushButton("Browse...")
        self.browse_button.setFixedWidth(100)
        self.browse_button.clicked.connect(self.browse_directory)
        dir_input_layout.addWidget(self.dir_label)
        dir_input_layout.addWidget(self.dir_entry)
        dir_input_layout.addWidget(self.browse_button)
        directory_analysis_layout.addLayout(dir_input_layout)

        # Analysis and Anonymized Text areas side by side
        local_results_layout = QHBoxLayout()
        # Analysis
        local_analysis_vbox = QVBoxLayout()
        local_analysis_label = QLabel("Analysis Results:")
        self.analysis_text = QTextEdit()
        self.analysis_text.setReadOnly(True)
        self.analysis_text.setPlaceholderText("Analysis results will appear here...")
        local_analysis_vbox.addWidget(local_analysis_label)
        local_analysis_vbox.addWidget(self.analysis_text)
        local_results_layout.addLayout(local_analysis_vbox)
        # Anonymized
        local_anonymized_vbox = QVBoxLayout()
        local_anonymized_label = QLabel("Anonymized Data:")
        self.anonymized_text = QTextEdit()
        self.anonymized_text.setReadOnly(True)
        self.anonymized_text.setPlaceholderText("Anonymized data will appear here...")
        local_anonymized_vbox.addWidget(local_anonymized_label)
        local_anonymized_vbox.addWidget(self.anonymized_text)
        local_results_layout.addLayout(local_anonymized_vbox)

        directory_analysis_layout.addLayout(local_results_layout)

        # Buttons for local analysis
        local_buttons_layout = QHBoxLayout()
        self.run_local_analysis_button = QPushButton("Run Local Directory Analysis")
        self.clear_local_results_button = QPushButton("Clear Local Results")
        self.run_local_analysis_button.clicked.connect(self.start_local_analysis)
        self.clear_local_results_button.clicked.connect(self.clear_local_results)
        local_buttons_layout.addStretch(1)
        local_buttons_layout.addWidget(self.run_local_analysis_button)
        local_buttons_layout.addWidget(self.clear_local_results_button)
        local_buttons_layout.addStretch(1)
        directory_analysis_layout.addLayout(local_buttons_layout)

        # GitHub Analysis Tab
        github_analysis_tab = QWidget()
        github_analysis_layout = QVBoxLayout()
        github_analysis_tab.setLayout(github_analysis_layout)
        self.tab_widget.addTab(github_analysis_tab, "GitHub Repository Analysis")

        github_label = QLabel("Enter a GitHub repository URL to clone and scan for PII.")
        github_analysis_layout.addWidget(github_label)

        github_repo_input_layout = QHBoxLayout()
        self.github_repo_label = QLabel("Repository URL:")
        self.github_repo_label.setFixedWidth(120)
        self.github_repo_entry = QLineEdit()
        self.github_repo_entry.setPlaceholderText("e.g., https://github.com/user/repo.git")
        github_repo_input_layout.addWidget(self.github_repo_label)
        github_repo_input_layout.addWidget(self.github_repo_entry)
        github_analysis_layout.addLayout(github_repo_input_layout)

        github_results_layout = QHBoxLayout()

        github_analysis_vbox = QVBoxLayout()
        github_analysis_label = QLabel("GitHub Analysis Results:")
        self.github_analysis_text = QTextEdit()
        self.github_analysis_text.setReadOnly(True)
        self.github_analysis_text.setPlaceholderText("Analysis results from GitHub repository will appear here...")
        github_analysis_vbox.addWidget(github_analysis_label)
        github_analysis_vbox.addWidget(self.github_analysis_text)
        github_results_layout.addLayout(github_analysis_vbox)

        github_anonymized_vbox = QVBoxLayout()
        github_anonymized_label = QLabel("GitHub Anonymized Data:")
        self.github_anonymized_text = QTextEdit()
        self.github_anonymized_text.setReadOnly(True)
        self.github_anonymized_text.setPlaceholderText("Anonymized data from GitHub repository will appear here...")
        github_anonymized_vbox.addWidget(github_anonymized_label)
        github_anonymized_vbox.addWidget(self.github_anonymized_text)
        github_results_layout.addLayout(github_anonymized_vbox)

        github_analysis_layout.addLayout(github_results_layout)

        github_buttons_layout = QHBoxLayout()
        self.run_github_analysis_button = QPushButton("Scan Repository")
        self.clear_github_results_button = QPushButton("Clear GitHub Results")
        self.run_github_analysis_button.clicked.connect(self.start_github_analysis)
        self.clear_github_results_button.clicked.connect(self.clear_github_results)
        github_buttons_layout.addStretch(1)
        github_buttons_layout.addWidget(self.run_github_analysis_button)
        github_buttons_layout.addWidget(self.clear_github_results_button)
        github_buttons_layout.addStretch(1)
        github_analysis_layout.addLayout(github_buttons_layout)

        self.setLayout(main_layout)

    def browse_directory(self):
        directory = QFileDialog.getExistingDirectory(self, "Select Directory")
        if directory:
            self.dir_entry.setText(directory)
            QMessageBox.information(self, "Directory Selected", f"Selected: {directory}")
        else:
            QMessageBox.information(self, "No Selection", "No directory was selected.")

    def start_local_analysis(self):
        indir = self.dir_entry.text()
        if not indir:
            QMessageBox.warning(self, "Input Error", "Please enter a directory path.")
            return
        if not os.path.isdir(indir):
            QMessageBox.warning(self, "Input Error", "The provided path is not a valid directory.")
            return
        self.analysis_text.setText("Analyzing local directory...")
        self.anonymized_text.setText("Anonymizing...")
        self.set_buttons_enabled(False)
        enable_groq_recheck = self.groq_recheck_checkbox.isChecked()
        append_to_files = self.append_files_switch.isChecked()
        self.worker = PIIAnalysisWorker(indir, enable_groq_recheck, append_to_files)
        self.worker.analysis_finished.connect(self.display_local_results)
        self.worker.analysis_error.connect(self.handle_local_analysis_error)
        self.worker.start()

    def start_github_analysis(self):
        repo_url = self.github_repo_entry.text()
        if not repo_url:
            QMessageBox.warning(self, "Input Error", "Please enter a GitHub repository URL.")
            return
        if not (repo_url.startswith("http://") or repo_url.startswith("https://")) or "github.com" not in repo_url:
            QMessageBox.warning(self, "Input Error",
                                "Please enter a valid GitHub repository URL (e.g., https://github.com/user/repo.git).")
            return
        self.github_analysis_text.setText("Cloning and analyzing GitHub repository...")
        self.github_anonymized_text.setText("Anonymizing...")
        self.set_buttons_enabled(False)
        enable_groq_recheck = self.groq_recheck_checkbox.isChecked()
        append_to_files = self.append_files_switch.isChecked()
        self.github_worker = GitHubAnalysisWorker(repo_url, enable_groq_recheck, append_to_files)
        self.github_worker.github_analysis_finished.connect(self.display_github_results)
        self.github_worker.github_analysis_error.connect(self.handle_github_analysis_error)
        self.github_worker.start()

    def display_local_results(self, analysis_results, anonymized_data):
        self.analysis_text.setText("\n".join(analysis_results) if analysis_results else "No sensitive data detected.")
        self.anonymized_text.setText("\n".join(anonymized_data) if anonymized_data else "No data to anonymize or no sensitive data found.")
        self.set_buttons_enabled(True)

    def display_github_results(self, analysis_results, anonymized_data):
        self.github_analysis_text.setText("\n".join(analysis_results) if analysis_results else "No sensitive data detected in GitHub repository.")
        self.github_anonymized_text.setText("\n".join(anonymized_data) if anonymized_data else "No data to anonymize or no sensitive data found in GitHub repository.")
        self.set_buttons_enabled(True)

    def handle_local_analysis_error(self, error_message):
        QMessageBox.critical(self, "Local Analysis Error", error_message)
        self.analysis_text.setText(f"Error: {error_message}")
        self.anonymized_text.setText("Error during anonymization.")
        self.set_buttons_enabled(True)

    def handle_github_analysis_error(self, error_message):
        QMessageBox.critical(self, "GitHub Analysis Error", error_message)
        self.github_analysis_text.setText(f"Error: {error_message}")
        self.github_anonymized_text.setText("Error during anonymization.")
        self.set_buttons_enabled(True)

    def clear_local_results(self):
        self.dir_entry.clear()
        self.analysis_text.clear()
        self.anonymized_text.clear()
        self.groq_recheck_checkbox.setChecked(False)
        self.append_files_switch.setChecked(False)
        QMessageBox.information(self, "Cleared", "Local directory analysis results and inputs cleared.")

    def clear_github_results(self):
        self.github_repo_entry.clear()
        self.github_analysis_text.clear()
        self.github_anonymized_text.clear()
        self.groq_recheck_checkbox.setChecked(False)
        self.append_files_switch.setChecked(False)
        QMessageBox.information(self, "Cleared", "GitHub analysis results and inputs cleared.")

    def set_buttons_enabled(self, enabled):
        self.run_local_analysis_button.setEnabled(enabled)
        self.browse_button.setEnabled(enabled)
        self.clear_local_results_button.setEnabled(enabled)
        self.run_github_analysis_button.setEnabled(enabled)
        self.clear_github_results_button.setEnabled(enabled)
        self.github_repo_entry.setEnabled(enabled)
        self.groq_recheck_checkbox.setEnabled(enabled)
        self.append_files_switch.setEnabled(enabled)

    def toggle_theme(self):
        if self.current_theme == "dark":
            self.current_theme = "light"
        else:
            self.current_theme = "dark"
        self.apply_theme(self.current_theme)

    def apply_theme(self, theme_name):
        if theme_name == "dark":
            qss = """
                QWidget {
                    font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
                    font-size: 14px;
                    color: #E0E0E0;
                    background-color: #222222;
                }
                QPushButton {
                    background-color: #007ACC;
                    color: white;
                    border-radius: 5px;
                    padding: 10px 20px;
                    font-weight: bold;
                    min-width: 120px;
                }
                QPushButton:hover {
                    background-color: #005F99;
                }
                QPushButton:pressed {
                    background-color: #004C7A;
                }
                QPushButton:disabled {
                    background-color: #666666;
                    color: #AAAAAA;
                }
                QLineEdit, QTextEdit {
                    background-color: #333333;
                    color: #F8F8F8;
                    border-radius: 4px;
                    border: 1px solid #454D55;
                    padding: 8px;
                }
                QLabel {
                    color: #DEE6ED;
                    font-weight: bold;
                }
                QTabWidget::pane {
                    border: 1px solid #444444;
                    background-color: #2B2B2B;
                    border-radius: 8px;
                }
                QTabBar::tab {
                    background-color: #333333;
                    color: #BBBBBB;
                    border-top-left-radius: 5px;
                    border-top-right-radius: 5px;
                    padding: 8px 24px;
                }
                QTabBar::tab:selected {
                    background-color: #252526;
                    color: #FFFFFF;
                }
                /* Styled Append to Files switch indicator */
                QCheckBox::indicator {
                    width: 40px;
                    height: 20px;
                    border-radius: 10px;
                    background: #555555;
                    border: 2px solid #777777;
                }
                QCheckBox::indicator:checked {
                    background: #007ACC;
                    border: 2px solid #007ACC;
                }
            """
        else:
            qss = """
                QWidget {
                    font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
                    font-size: 14px;
                    color: #222222;
                    background-color: #F8FAFB;
                }
                QPushButton {
                    background-color: #1976D2;
                    color: white;
                    border-radius: 5px;
                    padding: 10px 20px;
                    font-weight: bold;
                    min-width: 120px;
                }
                QPushButton:hover {
                    background-color: #125AB2;
                }
                QPushButton:pressed {
                    background-color: #0D3C74;
                }
                QPushButton:disabled {
                    background-color: #CCCCCC;
                    color: #666666;
                }
                QLineEdit, QTextEdit {
                    background-color: #FFFFFF;
                    color: #222222;
                    border-radius: 4px;
                    border: 1px solid #BBBBBB;
                    padding: 8px;
                }
                QLabel {
                    color: #2C3E50;
                    font-weight: bold;
                }
                QTabWidget::pane {
                    border: 1px solid #CCCCCC;
                    background-color: #FFFFFF;
                    border-radius: 8px;
                }
                QTabBar::tab {
                    background-color: #EFF2F4;
                    color: #555555;
                    border-top-left-radius: 5px;
                    border-top-right-radius: 5px;
                    padding: 8px 24px;
                }
                QTabBar::tab:selected {
                    background-color: #FFFFFF;
                    color: #1976D2;
                }
                /* Styled Append to Files switch indicator */
                QCheckBox::indicator {
                    width: 40px;
                    height: 20px;
                    border-radius: 10px;
                    background: #AAAAAA;
                    border: 2px solid #999999;
                }
                QCheckBox::indicator:checked {
                    background: #1976D2;
                    border: 2px solid #1976D2;
                }
            """
        self.setStyleSheet(qss)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PIIAnalyzerApp()
    window.show()
    sys.exit(app.exec_())

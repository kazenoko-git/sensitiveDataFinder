import sys, os, shutil, tempfile, json, time, hashlib, requests
from datetime import datetime
from typing import Union
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLineEdit, QTextEdit, QFileDialog, QTabWidget,
    QProgressBar, QMessageBox, QRadioButton, QGroupBox, QCheckBox,
    QLabel, QSlider, QScrollArea
)
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5.QtGui import QFont


# --- Mocking External Libraries for Demonstration ---
# Replace these with your actual Presidio, XposedOrNot, HIBP integrations
# For a real application, ensure you have 'presidio-analyzer', 'requests' installed
# and proper API keys for HIBP if needed.

class MockAnalyzer:
    """A mock Presidio analyzer for demonstration purposes."""

    def analyze(self, text, entities=None):
        results = []
        # Simulate finding sensitive data
        if "secret_key_123" in text:
            results.append({"entity_type": "API_KEY", "start": text.find("secret_key_123"),
                            "end": text.find("secret_key_123") + len("secret_key_123"), "score": 0.9,
                            "text": "secret_key_123"})
        if "john.doe@example.com" in text:
            results.append({"entity_type": "EMAIL_ADDRESS", "start": text.find("john.doe@example.com"),
                            "end": text.find("john.doe@example.com") + len("john.doe@example.com"), "score": 0.8,
                            "text": "john.doe@example.com"})
        if "breached@example.com" in text:
            results.append({"entity_type": "EMAIL_ADDRESS", "start": text.find("breached@example.com"),
                            "end": text.find("breached@example.com") + len("breached@example.com"), "score": 0.85,
                            "text": "breached@example.com"})
        if "password123" in text:
            results.append({"entity_type": "PASSWORD", "start": text.find("password123"),
                            "end": text.find("password123") + len("password123"), "score": 0.75, "text": "password123"})

        # Filter by requested entities if provided
        if entities:
            results = [r for r in results if r['entity_type'] in entities]
        return results

    def set_min_score_for_entity_type(self, score):
        print(f"Mock Analyzer: Setting min score to {score}")


def initialize_presidio_analyzer():
    """Initializes and returns a Presidio Analyzer (mocked for this example)."""
    print("Initializing Presidio Analyzer...")
    # In a real app:
    # from presidio_analyzer import AnalyzerEngine
    # analyzer = AnalyzerEngine()
    # return analyzer
    return MockAnalyzer()


def find_sensitive_data_with_presidio(text: str, analyzer: MockAnalyzer, entities: list = None) -> list:
    """
    Finds sensitive data in text using Presidio Analyzer.
    Returns a list of finding dictionaries.
    """
    # In a real app, you might want to map Presidio's output to your desired format
    # For now, directly use the mock analyzer's output structure.
    return analyzer.analyze(text, entities)


def check_email_with_xon(email_address: str) -> dict:
    """
    Checks if an email address has been compromised using XposedOrNot Community API.
    Returns a dictionary with 'breached' (bool) and 'details' (dict, if breached).
    """
    XON_EMAIL_API_URL = "https://api.xposedornot.com/v1/email/"
    HEADERS = {"User-Agent": "SensitiveDataFinderGUI/1.0 (Contact: your_email@example.com)"}

    try:
        response = requests.get(f"{XON_EMAIL_API_URL}{email_address}", headers=HEADERS, timeout=5)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        data = response.json()

        if "metrics" in data and data["metrics"]:
            return {"breached": True, "details": data["metrics"]}
        elif "message" in data and "No data found" in data["message"]:
            return {"breached": False}
        else:
            return {"breached": False, "error": "Unexpected API response", "raw_response": data}

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            return {"breached": False}
        elif e.response.status_code == 429:
            return {"breached": False, "error": "Rate limited by XposedOrNot. Please wait."}
        else:
            return {"breached": False, "error": f"HTTP Error {e.response.status_code}: {e.response.text}"}
    except requests.exceptions.RequestException as e:
        return {"breached": False, "error": f"Network error: {e}"}
    except ValueError:
        return {"breached": False, "error": "Invalid JSON response from XposedOrNot."}


def check_password_with_hibp(password: str) -> int:
    """
    Checks if a password has been compromised using HIBP Pwned Passwords API.
    Returns the count of times the password was found, or -1 on error.
    """
    HIBP_PASSWORDS_API_URL = "https://api.pwnedpasswords.com/range/"
    HEADERS = {
        "User-Agent": "SensitiveDataFinderGUI/1.0 (Contact: your_email@example.com)"}  # No API key needed for this endpoint

    hashed_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = hashed_password[:5]
    suffix = hashed_password[5:]

    try:
        response = requests.get(f"{HIBP_PASSWORDS_API_URL}{prefix}", headers=HEADERS, timeout=5)
        response.raise_for_status()

        if response.status_code == 200:
            lines = response.text.splitlines()
            for line in lines:
                line_suffix, count = line.split(':')
                if line_suffix == suffix:
                    return int(count)
            return 0
        elif response.status_code == 404:
            return 0
        else:
            return -1  # Indicate an API error
    except requests.exceptions.RequestException as e:
        return -1  # Network or other request error


# Import GitPython (assuming it's installed)
try:
    from git import Repo, InvalidGitRepositoryError, GitCommandError
except ImportError:
    QMessageBox.critical(None, "Import Error", "GitPython library not found. Please install it: pip install GitPython")
    sys.exit(1)


# --- Scanner Worker Thread ---
class ScannerWorker(QThread):
    """
    Worker thread to perform scanning operations to keep the GUI responsive.
    Emits signals for progress, findings, and completion.
    """
    progress_updated = pyqtSignal(int)
    status_updated = pyqtSignal(str)
    finding_found = pyqtSignal(dict)
    scan_finished = pyqtSignal(str)
    scan_error = pyqtSignal(str)

    def __init__(self, scan_type: str, path: str, scan_history: bool,
                 presidio_analyzer, settings: dict):
        super().__init__()
        self.scan_type = scan_type
        self.path = path
        self.scan_history = scan_history
        self.presidio_analyzer = presidio_analyzer
        self.settings = settings
        self._is_running = True

    def stop(self):
        self._is_running = False

    def run(self):
        self.status_updated.emit("Scan started...")
        self.progress_updated.emit(0)
        all_findings = []
        try:
            if self.scan_type == "local_file":
                all_findings = self._scan_local_file()
            elif self.scan_type == "local_directory":
                all_findings = self._scan_local_directory()
            elif self.scan_type == "remote_git" or self.scan_type == "local_git":
                all_findings = self._scan_git_repository()

            summary_message = f"Scan finished. Found {len(all_findings)} sensitive items."
            self.scan_finished.emit(summary_message)

        except Exception as e:
            self.scan_error.emit(f"An error occurred during scan: {e}")
        finally:
            self.progress_updated.emit(100)

    def _scan_local_file(self) -> list:
        """Scans a single local file."""
        findings = []
        file_path = self.path
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            raise ValueError(f"File not found or is not a file: {file_path}")

        self.status_updated.emit(f"Scanning file: {file_path}")
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                file_findings = find_sensitive_data_with_presidio(content, self.presidio_analyzer)
                for f in file_findings:
                    finding_record = self._create_finding_record(f, file_path, content)
                    self.finding_found.emit(finding_record)
                    findings.append(finding_record)
        except Exception as e:
            self.status_updated.emit(f"Error scanning file {file_path}: {e}")
        return findings

    def _scan_local_directory(self) -> list:
        """Scans a local directory recursively."""
        findings = []
        if not os.path.exists(self.path) or not os.path.isdir(self.path):
            raise ValueError(f"Directory not found or is not a directory: {self.path}")

        total_files = sum([len(files) for r, d, files in os.walk(self.path)])
        scanned_count = 0

        for root, _, files in os.walk(self.path):
            if not self._is_running: return []  # Allow stopping
            for file_name in files:
                if not self._is_running: return []  # Allow stopping
                file_path_abs = os.path.join(root, file_name)
                file_path_relative = os.path.relpath(file_path_abs, self.path)

                if not self._should_scan_file(file_path_relative):
                    self.status_updated.emit(f"Skipping: {file_path_relative}")
                    scanned_count += 1
                    self.progress_updated.emit(int((scanned_count / total_files) * 100))
                    continue

                self.status_updated.emit(f"Scanning: {file_path_relative}")
                try:
                    with open(file_path_abs, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        file_findings = find_sensitive_data_with_presidio(content, self.presidio_analyzer)
                        for f in file_findings:
                            finding_record = self._create_finding_record(f, file_path_relative, content)
                            self.finding_found.emit(finding_record)
                            findings.append(finding_record)
                except Exception as e:
                    self.status_updated.emit(f"Error scanning {file_path_relative}: {e}")

                scanned_count += 1
                self.progress_updated.emit(int((scanned_count / total_files) * 100))
        return findings

    def _scan_git_repository(self) -> list:
        """Scans a Git repository (local or remote, with optional history)."""
        findings = []
        temp_repo_dir = None
        repo = None

        try:
            if self.scan_type == "local_git":
                if not os.path.exists(self.path) or not os.path.isdir(self.path) or not os.path.exists(
                        os.path.join(self.path, '.git')):
                    raise ValueError(f"Local Git repository not found or invalid: {self.path}")
                self.status_updated.emit(f"Opening local Git repository: {self.path}")
                repo = Repo(self.path)
            else:  # remote_git
                self.status_updated.emit(f"Cloning remote Git repository: {self.path}")
                temp_repo_dir = tempfile.mkdtemp(prefix="git_scan_temp_")
                repo = Repo.clone_from(self.path, temp_repo_dir)
                self.status_updated.emit(f"Repository cloned to: {temp_repo_dir}")

            if repo.bare:
                raise ValueError("Cannot scan a bare Git repository.")

            commits_to_scan = list(repo.iter_commits()) if self.scan_history else [repo.head.commit]
            total_commits = len(commits_to_scan)
            processed_commits = 0

            for commit in commits_to_scan:
                if not self._is_running: return []  # Allow stopping
                self.status_updated.emit(
                    f"Processing commit: {commit.hexsha[:7]} by {commit.author.name} ({processed_commits + 1}/{total_commits})")

                # Get files from the current commit's tree
                for item in commit.tree.traverse():
                    if not self._is_running: return []  # Allow stopping
                    if item.type == 'blob':  # It's a file
                        file_path = item.path
                        if not self._should_scan_file(file_path):
                            continue

                        content = self._get_blob_content(item)
                        if content is None:  # Skipped (e.g., binary) or error
                            continue

                        file_findings = find_sensitive_data_with_presidio(content, self.presidio_analyzer)
                        for f in file_findings:
                            finding_record = self._create_finding_record(
                                f, file_path, content,
                                commit_hash=commit.hexsha,
                                commit_author=commit.author.name,
                                commit_date=commit.authored_datetime.isoformat()
                            )
                            self.finding_found.emit(finding_record)
                            findings.append(finding_record)

                processed_commits += 1
                self.progress_updated.emit(int((processed_commits / total_commits) * 100))

        except InvalidGitRepositoryError:
            raise ValueError(f"The path '{self.path}' is not a valid Git repository.")
        except GitCommandError as e:
            raise ValueError(f"Git command error: {e}")
        except Exception as e:
            raise e  # Re-raise other exceptions for general error handling
        finally:
            if temp_repo_dir and os.path.exists(temp_repo_dir):
                self.status_updated.emit(f"Cleaning up temporary directory: {temp_repo_dir}")
                shutil.rmtree(temp_repo_dir)
        return findings

    def _get_blob_content(self, blob) -> Union[str, None]:
        """Reads content from a GitPython blob object, handling potential binaries."""
        try:
            # Read a small chunk to check if it's likely text
            first_bytes = blob.data_stream.read(100)
            blob.data_stream.seek(0)  # Reset stream position

            if not first_bytes.isascii() and b'\x00' in first_bytes:  # Simple heuristic for binary
                self.status_updated.emit(f"    Skipping binary file: {blob.path}")
                return None
            return blob.data_stream.read().decode('utf-8', errors='ignore')
        except Exception as e:
            self.status_updated.emit(f"    Error reading blob {blob.path}: {e}")
            return None

    def _should_scan_file(self, filepath: str) -> bool:
        """Determines if a file should be scanned based on settings."""
        excluded_patterns = self.settings.get('excluded_patterns', [])
        included_extensions = self.settings.get('included_extensions', [])

        # Check exclusions first
        for pattern in excluded_patterns:
            if pattern and pattern in filepath:  # Simple substring match for now
                return False

        # Check inclusions
        if included_extensions:
            _, ext = os.path.splitext(filepath)
            return ext.lower() in [e.lower() for e in included_extensions if e]

        return True  # If no inclusions specified, scan all non-excluded

    def _create_finding_record(self, presidio_finding: dict, file_path: str, content: str,
                               commit_hash: str = "N/A", commit_author: str = "N/A", commit_date: str = "N/A") -> dict:
        """Helper to create a standardized finding record."""
        finding_record = {
            "file_path": file_path,
            "commit_hash": commit_hash,
            "commit_author": commit_author,
            "commit_date": commit_date,
            "entity_type": presidio_finding['entity_type'],
            "sensitive_text": presidio_finding['text'],
            "confidence": presidio_finding['score'],
            "location_start": presidio_finding['start'],
            "location_end": presidio_finding['end'],
            "context": content[max(0, presidio_finding['start'] - 50):presidio_finding['end'] + 50].replace('\n', ' ')
            # Snippet for context
        }

        # Add external breach checks
        if presidio_finding['entity_type'] == "EMAIL_ADDRESS":
            xon_result = check_email_with_xon(presidio_finding['text'])
            finding_record["breach_status_xon"] = xon_result.get("breached", False)
            if xon_result.get("breached"):
                finding_record["breach_details_xon"] = xon_result.get("details", {})
            else:
                finding_record["breach_check_error_xon"] = xon_result.get("error", "")
        elif presidio_finding['entity_type'] == "PASSWORD":
            hibp_count = check_password_with_hibp(presidio_finding['text'])
            finding_record["pwned_passwords_count"] = hibp_count
            if hibp_count == -1:
                finding_record["pwned_passwords_error"] = "Error checking HIBP Pwned Passwords."

        return finding_record


# --- Main GUI Application ---
class SensitiveDataFinderApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Sensitive Data Finder")
        self.setGeometry(100, 100, 900, 700)  # Increased size
        self.presidio_analyzer = initialize_presidio_analyzer()
        self.current_scan_worker = None
        self.all_findings = []
        self.settings_file = "app_settings.json"
        self.settings = self._load_settings()

        self._init_ui()
        self._apply_settings_to_analyzer()

    def _init_ui(self):
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)

        self.tab_widget = QTabWidget()
        self.main_layout.addWidget(self.tab_widget)

        self._create_scan_tab()
        self._create_settings_tab()
        self._create_about_tab()

        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Ready to scan.")

    def _create_scan_tab(self):
        self.scan_tab = QWidget()
        self.tab_widget.addTab(self.scan_tab, "Scan")
        self.scan_layout = QVBoxLayout(self.scan_tab)

        # Input Path/URL
        path_layout = QHBoxLayout()
        self.path_input = QLineEdit()
        self.path_input.setPlaceholderText("Enter file/directory path or Git URL")
        path_layout.addWidget(self.path_input)

        self.browse_file_btn = QPushButton("Browse File")
        self.browse_file_btn.clicked.connect(self._browse_file)
        path_layout.addWidget(self.browse_file_btn)

        self.browse_dir_btn = QPushButton("Browse Dir")
        self.browse_dir_btn.clicked.connect(self._browse_directory)
        path_layout.addWidget(self.browse_dir_btn)
        self.scan_layout.addLayout(path_layout)

        # Scan Type Selection
        scan_type_group = QGroupBox("Scan Type")
        scan_type_layout = QHBoxLayout()
        self.radio_local_file = QRadioButton("Local File")
        self.radio_local_dir = QRadioButton("Local Directory")
        self.radio_local_git = QRadioButton("Local Git Repo")
        self.radio_remote_git = QRadioButton("Remote Git Repo")

        self.radio_local_file.setChecked(True)  # Default selection

        scan_type_layout.addWidget(self.radio_local_file)
        scan_type_layout.addWidget(self.radio_local_dir)
        scan_type_layout.addWidget(self.radio_local_git)
        scan_type_layout.addWidget(self.radio_remote_git)
        scan_type_group.setLayout(scan_type_layout)
        self.scan_layout.addWidget(scan_type_group)

        # Git History Option
        self.checkbox_scan_history = QCheckBox("Scan Git History (slower)")
        self.checkbox_scan_history.setChecked(True)  # Default to scan history
        self.scan_layout.addWidget(self.checkbox_scan_history)

        # Connect radio buttons to update Git history checkbox visibility
        self.radio_local_file.toggled.connect(self._update_git_options_visibility)
        self.radio_local_dir.toggled.connect(self._update_git_options_visibility)
        self.radio_local_git.toggled.connect(self._update_git_options_visibility)
        self.radio_remote_git.toggled.connect(self._update_git_options_visibility)
        self._update_git_options_visibility()  # Initial update

        # Control Buttons
        control_layout = QHBoxLayout()
        self.start_scan_btn = QPushButton("Start Scan")
        self.start_scan_btn.clicked.connect(self._start_scan)
        control_layout.addWidget(self.start_scan_btn)

        self.stop_scan_btn = QPushButton("Stop Scan")
        self.stop_scan_btn.clicked.connect(self._stop_scan)
        self.stop_scan_btn.setEnabled(False)  # Disabled until scan starts
        control_layout.addWidget(self.stop_scan_btn)
        self.scan_layout.addLayout(control_layout)

        # Progress Bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.scan_layout.addWidget(self.progress_bar)

        # Results Display
        self.results_display = QTextEdit()
        self.results_display.setReadOnly(True)
        self.results_display.setFont(QFont("Monospace", 10))
        self.scan_layout.addWidget(self.results_display)

    def _create_settings_tab(self):
        self.settings_tab = QWidget()
        self.tab_widget.addTab(self.settings_tab, "Settings")
        self.settings_layout = QVBoxLayout(self.settings_tab)

        # Presidio Confidence Threshold
        confidence_layout = QHBoxLayout()
        confidence_layout.addWidget(QLabel("Presidio Confidence Threshold:"))
        self.confidence_slider = QSlider(Qt.Horizontal)
        self.confidence_slider.setMinimum(0)
        self.confidence_slider.setMaximum(100)
        self.confidence_slider.setValue(int(self.settings.get('presidio_confidence', 0.75) * 100))
        self.confidence_slider.setTickInterval(10)
        self.confidence_slider.setTickPosition(QSlider.TicksBelow)
        self.confidence_slider.valueChanged.connect(self._update_confidence_label)
        confidence_layout.addWidget(self.confidence_slider)
        self.confidence_label = QLabel(f"{self.settings.get('presidio_confidence', 0.75):.2f}")
        confidence_layout.addWidget(self.confidence_label)
        self.settings_layout.addLayout(confidence_layout)

        # Excluded Patterns
        self.settings_layout.addWidget(
            QLabel("Excluded File/Directory Patterns (one per line, e.g., .git/, node_modules/, *.log):"))
        self.excluded_patterns_input = QTextEdit()
        self.excluded_patterns_input.setPlaceholderText("Enter patterns to exclude...")
        self.excluded_patterns_input.setText("\n".join(self.settings.get('excluded_patterns', [])))
        self.settings_layout.addWidget(self.excluded_patterns_input)

        # Included Extensions
        self.settings_layout.addWidget(QLabel("Included File Extensions (one per line, e.g., .py, .js, .txt):"))
        self.included_extensions_input = QTextEdit()
        self.included_extensions_input.setPlaceholderText("Enter extensions to include...")
        self.included_extensions_input.setText("\n".join(self.settings.get('included_extensions', [])))
        self.settings_layout.addWidget(self.included_extensions_input)

        # HIBP API Key (Optional)
        self.settings_layout.addWidget(QLabel("HIBP API Key (for email breach details, Pwned Passwords API is free):"))
        self.hibp_api_key_input = QLineEdit()
        self.hibp_api_key_input.setPlaceholderText("Enter your HIBP API key (optional)")
        self.hibp_api_key_input.setText(self.settings.get('hibp_api_key', ''))
        self.settings_layout.addWidget(self.hibp_api_key_input)
        self.settings_layout.addWidget(
            QLabel("Note: XposedOrNot email checks are generally free and do not require a key."))

        # Save Settings Button
        save_settings_btn = QPushButton("Save Settings")
        save_settings_btn.clicked.connect(self._save_settings)
        self.settings_layout.addWidget(save_settings_btn)
        self.settings_layout.addStretch(1)  # Push content to top

    def _create_about_tab(self):
        self.about_tab = QWidget()
        self.tab_widget.addTab(self.about_tab, "About")
        self.about_layout = QVBoxLayout(self.about_tab)

        about_text = QTextEdit()
        about_text.setReadOnly(True)
        about_text.setHtml("""
            <h2>Sensitive Data Finder</h2>
            <p>This application helps you scan files, directories, and Git repositories for sensitive information.</p>
            <h3>Features:</h3>
            <ul>
                <li><strong>Local File/Directory Scan:</strong> Scan content on your local machine.</li>
                <li><strong>Git Repository Scan:</strong> Scan local or remote Git repositories, including full commit history for exposed secrets.</li>
                <li><strong>External Breach Checks:</strong> Integrates with XposedOrNot (for email breaches) and Have I Been Pwned (for pwned passwords) to provide external context to findings.</li>
                <li><strong>Configurable:</strong> Adjust Presidio confidence, exclude/include file patterns, and manage API keys.</li>
            </ul>
            <h3>How it works:</h3>
            <p>It leverages the <a href="https://microsoft.github.io/Presidio/" style="color: blue;">Presidio</a> library for sensitive data detection, <a href="https://gitpython.readthedocs.io/en/stable/" style="color: blue;">GitPython</a> for Git interactions, and external APIs for breach intelligence.</p>
            <p><strong>Disclaimer:</strong> This tool is for educational and security assessment purposes. Always ensure you have proper authorization before scanning any data or repositories you do not own or manage. Be mindful of API rate limits.</p>
            <p>Version: 1.0</p>
        """)
        self.about_layout.addWidget(about_text)

    def _update_git_options_visibility(self):
        """Hides/shows Git-specific options based on selected scan type."""
        is_git_scan = self.radio_local_git.isChecked() or self.radio_remote_git.isChecked()
        self.checkbox_scan_history.setVisible(is_git_scan)

    def _browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Scan")
        if file_path:
            self.path_input.setText(file_path)
            self.radio_local_file.setChecked(True)

    def _browse_directory(self):
        dir_path = QFileDialog.getExistingDirectory(self, "Select Directory to Scan")
        if dir_path:
            self.path_input.setText(dir_path)
            self.radio_local_dir.setChecked(True)

    def _update_confidence_label(self, value):
        self.confidence_label.setText(f"{value / 100.0:.2f}")

    def _load_settings(self):
        """Loads settings from a JSON file."""
        if os.path.exists(self.settings_file):
            with open(self.settings_file, 'r') as f:
                return json.load(f)
        return {  # Default settings
            'presidio_confidence': 0.75,
            'excluded_patterns': ['.git/', '.DS_Store', '__pycache__/', '*.log', '*.lock', '*.min.js', '*.css.map',
                                  'node_modules/', '.venv/', '.vscode/', '.idea/', 'tmp/', 'temp/'],
            'included_extensions': ['.py', '.js', '.ts', '.java', '.cs', '.php', '.html', '.css', '.json', '.yaml',
                                    '.yml', '.xml', '.txt', '.md', '.env', '.conf', '.config', '.sql'],
            'hibp_api_key': ''
        }

    def _save_settings(self):
        """Saves settings to a JSON file."""
        self.settings['presidio_confidence'] = self.confidence_slider.value() / 100.0
        self.settings['excluded_patterns'] = [line.strip() for line in
                                              self.excluded_patterns_input.toPlainText().split('\n') if line.strip()]
        self.settings['included_extensions'] = [line.strip() for line in
                                                self.included_extensions_input.toPlainText().split('\n') if
                                                line.strip()]
        self.settings['hibp_api_key'] = self.hibp_api_key_input.text().strip()

        with open(self.settings_file, 'w') as f:
            json.dump(self.settings, f, indent=4)
        self.status_bar.showMessage("Settings saved successfully!")
        self._apply_settings_to_analyzer()  # Apply immediately

    def _apply_settings_to_analyzer(self):
        """Applies current settings to the Presidio analyzer."""
        confidence = self.settings.get('presidio_confidence', 0.75)
        self.presidio_analyzer.set_min_score_for_entity_type(confidence)
        # For a real Presidio Analyzer, you'd configure it here.
        # Example: analyzer.set_analysis_parameters(min_score=confidence)
        # You might also need to re-initialize recognizers if custom ones are added based on settings.
        self.status_bar.showMessage(f"Analyzer confidence set to {confidence:.2f}")

    def _start_scan(self):
        if self.current_scan_worker and self.current_scan_worker.isRunning():
            QMessageBox.warning(self, "Scan in Progress", "A scan is already running. Please stop it first.")
            return

        path = self.path_input.text().strip()
        if not path:
            QMessageBox.warning(self, "Input Error", "Please enter a path or URL to scan.")
            return

        scan_type = ""
        if self.radio_local_file.isChecked():
            scan_type = "local_file"
        elif self.radio_local_dir.isChecked():
            scan_type = "local_directory"
        elif self.radio_local_git.isChecked():
            scan_type = "local_git"
        elif self.radio_remote_git.isChecked():
            scan_type = "remote_git"

        scan_history = self.checkbox_scan_history.isChecked() if (
                    scan_type == "local_git" or scan_type == "remote_git") else False

        self.results_display.clear()
        self.all_findings = []
        self.progress_bar.setValue(0)
        self.start_scan_btn.setEnabled(False)
        self.stop_scan_btn.setEnabled(True)
        self.status_bar.showMessage(f"Starting {scan_type} scan...")

        # Update HIBP API key in environment for the worker thread
        # This is important if the worker thread directly accesses os.environ
        # For a more robust solution, pass the key directly to the worker.
        os.environ['HIBP_API_KEY'] = self.settings.get('hibp_api_key', '')

        self.current_scan_worker = ScannerWorker(
            scan_type=scan_type,
            path=path,
            scan_history=scan_history,
            presidio_analyzer=self.presidio_analyzer,
            settings=self.settings  # Pass settings to worker
        )
        self.current_scan_worker.progress_updated.connect(self.progress_bar.setValue)
        self.current_scan_worker.status_updated.connect(self.status_bar.showMessage)
        self.current_scan_worker.finding_found.connect(self._display_finding)
        self.current_scan_worker.scan_finished.connect(self._scan_finished)
        self.current_scan_worker.scan_error.connect(self._scan_error)
        self.current_scan_worker.start()

    def _stop_scan(self):
        if self.current_scan_worker and self.current_scan_worker.isRunning():
            self.current_scan_worker.stop()
            self.current_scan_worker.wait()  # Wait for the thread to finish cleanly
            self.status_bar.showMessage("Scan stopped by user.")
            self.start_scan_btn.setEnabled(True)
            self.stop_scan_btn.setEnabled(False)

    def _display_finding(self, finding: dict):
        self.all_findings.append(finding)
        output_text = f"--- Finding ---\n"
        output_text += f"File: {finding.get('file_path', 'N/A')}\n"
        if finding.get('commit_hash') != "N/A":
            output_text += f"Commit: {finding.get('commit_hash', 'N/A')[:7]} by {finding.get('commit_author', 'N/A')} on {finding.get('commit_date', 'N/A')}\n"
        output_text += f"Type: {finding.get('entity_type', 'N/A')}\n"
        output_text += f"Text: '{finding.get('sensitive_text', 'N/A')}'\n"
        output_text += f"Confidence: {finding.get('confidence', 'N/A'):.2f}\n"
        output_text += f"Context: '{finding.get('context', 'N/A')}'\n"

        if finding.get('entity_type') == "EMAIL_ADDRESS":
            output_text += f"  Breached (XposedOrNot): {'YES' if finding.get('breach_status_xon') else 'NO'}\n"
            if finding.get('breach_status_xon'):
                details = finding.get('breach_details_xon', {})
                output_text += f"    XON Details: Breaches: {details.get('breaches_count', 'N/A')}, Pastes: {details.get('pastes_count', 'N/A')}\n"
            elif finding.get('breach_check_error_xon'):
                output_text += f"    XON Check Error: {finding.get('breach_check_error_xon')}\n"
        elif finding.get('entity_type') == "PASSWORD":
            pwned_count = finding.get('pwned_passwords_count', -1)
            if pwned_count > 0:
                output_text += f"  Pwned (HIBP): Found {pwned_count} times! (Strongly advise changing)\n"
            elif pwned_count == 0:
                output_text += f"  Pwned (HIBP): Not found in known breaches (good).\n"
            else:
                output_text += f"  Pwned (HIBP) Check Error: {finding.get('pwned_passwords_error', 'N/A')}\n"

        output_text += "---\n\n"
        self.results_display.append(output_text)

    def _scan_finished(self, message: str):
        self.status_bar.showMessage(message)
        self.start_scan_btn.setEnabled(True)
        self.stop_scan_btn.setEnabled(False)
        QMessageBox.information(self, "Scan Complete", message)

    def _scan_error(self, error_message: str):
        self.status_bar.showMessage(f"Scan Error: {error_message}")
        self.start_scan_btn.setEnabled(True)
        self.stop_scan_btn.setEnabled(False)
        QMessageBox.critical(self, "Scan Error", error_message)

    def closeEvent(self, event):
        """Handles application close event to stop running threads."""
        if self.current_scan_worker and self.current_scan_worker.isRunning():
            reply = QMessageBox.question(self, 'Confirm Exit',
                                         "A scan is in progress. Do you want to stop it and exit?",
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.Yes:
                self.current_scan_worker.stop()
                self.current_scan_worker.wait()  # Wait for thread to terminate
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()


if __name__ == "__main__":
    # Ensure 'requests' is installed for XposedOrNot/HIBP and 'GitPython' for Git
    # pip install requests GitPython PyQt5

    app = QApplication(sys.argv)
    window = SensitiveDataFinderApp()
    window.show()
    sys.exit(app.exec_())

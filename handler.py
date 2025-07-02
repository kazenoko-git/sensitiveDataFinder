import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLineEdit, QTextEdit, QLabel, QFileDialog, QMessageBox, QTabWidget, QSizePolicy, QCheckBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal

# Import the chk class from your main_script_py file
# Ensure main_script_py.py is in the same directory as this gui_app.py
try:
    from collector import chk
except ImportError:
    QMessageBox.critical(None, "Import Error",
                         "Could not import 'chk' class from 'main_script_py.py'. "
                         "Please ensure 'main_script_py.py' is in the same directory.")
    sys.exit(1)


# --- Worker Thread for PII Analysis ---
# Running the analysis in a separate thread prevents the GUI from freezing
# during long-running operations.
class PIIAnalysisWorker(QThread):
    # Signals to communicate results back to the GUI thread
    analysis_finished = pyqtSignal(list, list)
    analysis_error = pyqtSignal(str)

    def __init__(self, indir, enable_groq_recheck):
        super().__init__()
        self.indir = indir
        self.enable_groq_recheck = enable_groq_recheck

    def run(self):
        try:
            # Create an instance of the chk class and run the analysis
            analyzer = chk()
            # Pass the enable_groq_recheck flag to the check method
            analysis_results, anonymized_data = analyzer.check(self.indir, self.enable_groq_recheck)

            # --- Debugging and Type Checking ---
            print(f"Worker: Type of analysis_results before emit: {type(analysis_results)}")
            print(f"Worker: Type of anonymized_data before emit: {type(anonymized_data)}")

            # Ensure analysis_results is a list
            if not isinstance(analysis_results, list):
                print(f"Worker Warning: analysis_results is not a list. Converting to list: {type(analysis_results)}")
                analysis_results = [str(analysis_results)]  # Convert to a list containing its string representation

            # Ensure anonymized_data is a list
            if not isinstance(anonymized_data, list):
                print(f"Worker Warning: anonymized_data is not a list. Converting to list: {type(anonymized_data)}")
                anonymized_data = [str(anonymized_data)]  # Convert to a list containing its string representation
            # --- End Debugging and Type Checking ---

            self.analysis_finished.emit(analysis_results, anonymized_data)
        except Exception as e:
            self.analysis_error.emit(f"An error occurred during analysis: {e}")


# --- Main GUI Application Class ---
class PIIAnalyzerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PII Analyzer")
        self.setGeometry(100, 100, 1000, 700)  # Initial window size
        self.setMinimumSize(800, 600)  # Set a minimum size

        self.current_theme = "dark"  # Track current theme
        self.init_ui()
        self.apply_theme(self.current_theme)  # Apply initial theme

    def init_ui(self):
        print("Initializing UI...")  # Debug print at the start of UI initialization
        # Main layout for the entire application
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(20, 20, 20, 20)  # Add padding around the main window
        main_layout.setSpacing(15)  # Spacing between major elements

        # Top bar with theme toggle and Groq recheck checkbox
        top_bar_layout = QHBoxLayout()
        top_bar_layout.addStretch(1)  # Pushes elements to the right

        # Groq Recheck Checkbox
        self.groq_recheck_checkbox = QCheckBox("Enable Groq Recheck")
        self.groq_recheck_checkbox.setChecked(False)  # Default to disabled
        top_bar_layout.addWidget(self.groq_recheck_checkbox)

        # Theme toggle button
        self.theme_toggle_button = QPushButton("Toggle Light/Dark Mode")
        self.theme_toggle_button.clicked.connect(self.toggle_theme)
        top_bar_layout.addWidget(self.theme_toggle_button)
        main_layout.addLayout(top_bar_layout)

        # Tab Widget for different functionalities
        self.tab_widget = QTabWidget()
        self.tab_widget.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        main_layout.addWidget(self.tab_widget)

        # --- Text Analysis Tab ---
        text_analysis_tab = QWidget()
        text_analysis_layout = QVBoxLayout()
        text_analysis_layout.setContentsMargins(15, 15, 15, 15)
        text_analysis_layout.setSpacing(10)
        text_analysis_tab.setLayout(text_analysis_layout)
        self.tab_widget.addTab(text_analysis_tab, "Text Analysis")

        # Input for Directory Path
        dir_input_layout = QHBoxLayout()
        dir_input_layout.setSpacing(10)
        self.dir_label = QLabel("Input Directory:")
        self.dir_label.setFixedWidth(120)  # Align labels
        self.dir_entry = QLineEdit()
        self.dir_entry.setPlaceholderText("Enter path or browse for a directory")
        self.browse_button = QPushButton("Browse...")
        self.browse_button.setFixedWidth(100)  # Consistent button width
        print("Attempting to connect browse_button...")  # Debug print
        self.browse_button.clicked.connect(self.browse_directory)

        dir_input_layout.addWidget(self.dir_label)
        dir_input_layout.addWidget(self.dir_entry)
        dir_input_layout.addWidget(self.browse_button)
        text_analysis_layout.addLayout(dir_input_layout)

        # Analysis and Anonymized Data Display
        results_layout = QHBoxLayout()
        results_layout.setSpacing(15)

        # Analysis Results
        analysis_vbox = QVBoxLayout()
        analysis_label = QLabel("Analysis Results:")
        self.analysis_text = QTextEdit()
        self.analysis_text.setReadOnly(True)
        self.analysis_text.setPlaceholderText("Analysis results will appear here...")
        analysis_vbox.addWidget(analysis_label)
        analysis_vbox.addWidget(self.analysis_text)
        results_layout.addLayout(analysis_vbox)

        # Anonymized Data
        anonymized_vbox = QVBoxLayout()
        anonymized_label = QLabel("Anonymized Data:")
        self.anonymized_text = QTextEdit()
        self.anonymized_text.setReadOnly(True)
        self.anonymized_text.setPlaceholderText("Anonymized data will appear here...")
        anonymized_vbox.addWidget(anonymized_label)
        anonymized_vbox.addWidget(self.anonymized_text)
        results_layout.addLayout(anonymized_vbox)

        text_analysis_layout.addLayout(results_layout)

        # Buttons for Text Analysis
        text_buttons_layout = QHBoxLayout()
        text_buttons_layout.setSpacing(10)
        self.run_analysis_button = QPushButton("Run Text Analysis")
        self.clear_button = QPushButton("Clear Results")
        print("Attempting to connect run_analysis_button...")  # Debug print for run_analysis_button
        self.run_analysis_button.clicked.connect(self.start_analysis)

        text_buttons_layout.addStretch(1)  # Pushes buttons to the right
        text_buttons_layout.addWidget(self.run_analysis_button)
        text_buttons_layout.addWidget(self.clear_button)
        text_buttons_layout.addStretch(1)
        text_analysis_layout.addLayout(text_buttons_layout)

        # --- Image Analysis Tab (Placeholder) ---
        image_analysis_tab = QWidget()
        image_analysis_layout = QVBoxLayout()
        image_analysis_layout.setContentsMargins(15, 15, 15, 15)
        image_analysis_layout.setSpacing(10)
        image_analysis_tab.setLayout(image_analysis_layout)
        self.tab_widget.addTab(image_analysis_tab, "Image Analysis")

        image_label = QLabel("Image Analysis functionality will be added here.")
        image_analysis_layout.addWidget(image_label)

        image_file_input_layout = QHBoxLayout()
        image_file_input_layout.setSpacing(10)
        self.image_file_label = QLabel("Image File:")
        self.image_file_label.setFixedWidth(120)
        self.image_file_entry = QLineEdit()
        self.image_file_entry.setPlaceholderText("Select an image file")
        self.browse_image_button = QPushButton("Browse Image...")
        self.browse_image_button.setFixedWidth(120)
        print("Attempting to connect browse_image_button...")  # Debug print
        self.browse_image_button.clicked.connect(self.browse_image_file)
        image_file_input_layout.addWidget(self.image_file_label)
        image_file_input_layout.addWidget(self.image_file_entry)
        image_file_input_layout.addWidget(self.browse_image_button)
        image_analysis_layout.addLayout(image_file_input_layout)

        self.run_image_analysis_button = QPushButton("Run Image Analysis (Coming Soon)")
        self.run_image_analysis_button.clicked.connect(self.show_coming_soon_message)
        image_analysis_layout.addWidget(self.run_image_analysis_button, alignment=Qt.AlignCenter)
        image_analysis_layout.addStretch(1)  # Push content to top

        # --- PDF Analysis Tab (Placeholder) ---
        pdf_analysis_tab = QWidget()
        pdf_analysis_layout = QVBoxLayout()
        pdf_analysis_layout.setContentsMargins(15, 15, 15, 15)
        pdf_analysis_layout.setSpacing(10)
        pdf_analysis_tab.setLayout(pdf_analysis_layout)
        self.tab_widget.addTab(pdf_analysis_tab, "PDF Analysis")

        pdf_label = QLabel("PDF Analysis functionality will be added here.")
        pdf_analysis_layout.addWidget(pdf_label)

        pdf_file_input_layout = QHBoxLayout()
        pdf_file_input_layout.setSpacing(10)
        self.pdf_file_label = QLabel("PDF File:")
        self.pdf_file_label.setFixedWidth(120)
        self.pdf_file_entry = QLineEdit()
        self.pdf_file_entry.setPlaceholderText("Select a PDF file")
        self.browse_pdf_button = QPushButton("Browse PDF...")
        self.browse_pdf_button.setFixedWidth(120)
        print("Attempting to connect browse_pdf_button...")  # Debug print
        self.browse_pdf_button.clicked.connect(self.browse_pdf_file)
        pdf_file_input_layout.addWidget(self.pdf_file_label)
        pdf_file_input_layout.addWidget(self.pdf_file_entry)
        pdf_file_input_layout.addWidget(self.browse_pdf_button)
        pdf_analysis_layout.addLayout(pdf_file_input_layout)

        self.run_pdf_analysis_button = QPushButton("Run PDF Analysis (Coming Soon)")
        self.run_pdf_analysis_button.clicked.connect(self.show_coming_soon_message)
        pdf_analysis_layout.addWidget(self.run_pdf_analysis_button, alignment=Qt.AlignCenter)
        pdf_analysis_layout.addStretch(1)  # Push content to top

        # --- GitHub Repository Analysis Tab (NEW) ---
        github_analysis_tab = QWidget()
        github_analysis_layout = QVBoxLayout()
        github_analysis_layout.setContentsMargins(15, 15, 15, 15)
        github_analysis_layout.setSpacing(10)
        github_analysis_tab.setLayout(github_analysis_layout)
        self.tab_widget.addTab(github_analysis_tab, "GitHub Analysis")

        github_label = QLabel("GitHub Repository Analysis functionality will be added here.")
        github_analysis_layout.addWidget(github_label)

        github_repo_input_layout = QHBoxLayout()
        github_repo_input_layout.setSpacing(10)
        self.github_repo_label = QLabel("Repository URL:")
        self.github_repo_label.setFixedWidth(120)
        self.github_repo_entry = QLineEdit()
        self.github_repo_entry.setPlaceholderText("e.g., https://github.com/user/repo")
        github_repo_input_layout.addWidget(self.github_repo_label)
        github_repo_input_layout.addWidget(self.github_repo_entry)
        github_analysis_layout.addLayout(github_repo_input_layout)

        self.run_github_analysis_button = QPushButton("Scan Repository (Coming Soon)")
        self.run_github_analysis_button.clicked.connect(self.show_coming_soon_message)
        github_analysis_layout.addWidget(self.run_github_analysis_button, alignment=Qt.AlignCenter)
        github_analysis_layout.addStretch(1)

        # --- Email Data Leak Search Tab (NEW) ---
        email_leak_tab = QWidget()
        email_leak_layout = QVBoxLayout()
        email_leak_layout.setContentsMargins(15, 15, 15, 15)
        email_leak_layout.setSpacing(10)
        email_leak_tab.setLayout(email_leak_layout)
        self.tab_widget.addTab(email_leak_tab, "Email Leak Search")

        email_leak_label = QLabel("Email Data Leak Search functionality will be added here.")
        email_leak_layout.addWidget(email_leak_label)

        email_input_layout = QHBoxLayout()
        email_input_layout.setSpacing(10)
        self.email_label = QLabel("Email Address:")
        self.email_label.setFixedWidth(120)
        self.email_entry = QLineEdit()
        self.email_entry.setPlaceholderText("e.g., example@domain.com")
        email_input_layout.addWidget(self.email_label)
        email_input_layout.addWidget(self.email_entry)
        email_leak_layout.addLayout(email_input_layout)

        self.run_email_leak_button = QPushButton("Search Data Leaks (Coming Soon)")
        self.run_email_leak_button.clicked.connect(self.show_coming_soon_message)
        email_leak_layout.addWidget(self.run_email_leak_button, alignment=Qt.AlignCenter)
        email_leak_layout.addStretch(1)

        self.setLayout(main_layout)

    def browse_directory(self):
        print("Inside browse_directory function!")  # Debug print
        directory = QFileDialog.getExistingDirectory(self, "Select Directory")
        if directory:
            self.dir_entry.setText(directory)
            QMessageBox.information(self, "Directory Selected", f"Selected: {directory}")
        else:
            QMessageBox.information(self, "No Selection", "No directory was selected.")

    def browse_image_file(self):
        print("Inside browse_image_file function!")  # Debug print
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Image File", "",
                                                   "Image Files (*.png *.jpg *.jpeg *.gif)")
        if file_path:
            self.image_file_entry.setText(file_path)
            QMessageBox.information(self, "Image File Selected", f"Selected: {file_path}")
        else:
            QMessageBox.information(self, "No Selection", "No image file was selected.")

    def browse_pdf_file(self):
        print("Inside browse_pdf_file function!")  # Debug print
        file_path, _ = QFileDialog.getOpenFileName(self, "Select PDF File", "", "PDF Files (*.pdf)")
        if file_path:
            self.pdf_file_entry.setText(file_path)
            QMessageBox.information(self, "PDF File Selected", f"Selected: {file_path}")
        else:
            QMessageBox.information(self, "No Selection", "No PDF file was selected.")

    def start_analysis(self):
        print("Inside start_analysis function!")  # Debug print for start_analysis
        indir = self.dir_entry.text()
        if not indir:
            QMessageBox.warning(self, "Input Error", "Please enter a directory path.")
            return

        self.analysis_text.setText("Analyzing...")
        self.anonymized_text.setText("Anonymizing...")
        self.set_buttons_enabled(False)  # Disable buttons during analysis

        # Get Groq recheck state from the checkbox
        enable_groq_recheck = self.groq_recheck_checkbox.isChecked()

        # Create and start the worker thread, passing the Groq recheck state
        self.worker = PIIAnalysisWorker(indir, enable_groq_recheck)
        self.worker.analysis_finished.connect(self.display_results)
        self.worker.analysis_error.connect(self.handle_analysis_error)
        self.worker.start()

    def display_results(self, analysis_results, anonymized_data):
        # Display analysis results
        if analysis_results:
            self.analysis_text.setText("\n".join(analysis_results))
        else:
            self.analysis_text.setText("No sensitive data detected.")

        # Display anonymized data
        if anonymized_data:
            self.anonymized_text.setText("\n".join(anonymized_data))
        else:
            self.anonymized_text.setText("No data to anonymize or no sensitive data found.")

        self.set_buttons_enabled(True)  # Re-enable buttons

    def handle_analysis_error(self, error_message):
        QMessageBox.critical(self, "Analysis Error", error_message)
        self.analysis_text.setText(f"Error: {error_message}")
        self.anonymized_text.setText("Error during anonymization.")
        self.set_buttons_enabled(True)  # Re-enable buttons

    def clear_results(self):
        self.dir_entry.clear()
        self.analysis_text.clear()
        self.anonymized_text.clear()
        self.image_file_entry.clear()
        self.pdf_file_entry.clear()
        self.github_repo_entry.clear()  # Clear new entries
        self.email_entry.clear()  # Clear new entries
        self.groq_recheck_checkbox.setChecked(False)  # Reset Groq recheck checkbox
        QMessageBox.information(self, "Cleared", "All results and inputs cleared.")

    def show_coming_soon_message(self):
        QMessageBox.information(self, "Feature Coming Soon",
                                "This feature is under development and will be available in a future update!")

    def set_buttons_enabled(self, enabled):
        self.run_analysis_button.setEnabled(enabled)
        self.browse_button.setEnabled(enabled)
        self.clear_button.setEnabled(enabled)
        self.groq_recheck_checkbox.setEnabled(enabled)  # Enable/disable checkbox
        # Disable placeholder buttons as well if analysis is running
        self.run_image_analysis_button.setEnabled(enabled)
        self.browse_image_button.setEnabled(enabled)
        self.run_pdf_analysis_button.setEnabled(enabled)
        self.browse_pdf_button.setEnabled(enabled)
        self.run_github_analysis_button.setEnabled(enabled)  # New button
        self.run_email_leak_button.setEnabled(enabled)  # New button

    def toggle_theme(self):
        if self.current_theme == "dark":
            self.apply_theme("light")
            self.current_theme = "light"
        else:
            self.apply_theme("dark")
            self.current_theme = "dark"

    def apply_theme(self, theme_name):
        if theme_name == "dark":
            qss = """
                QWidget {
                    font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
                    font-size: 14px;
                    color: #E0E0E0; /* Light gray text for dark mode */
                    background-color: #2B2B2B; /* Dark gray background */
                }

                /* Main Window */
                PIIAnalyzerApp {
                    background-color: #1E1E1E; /* Even darker background for the main window */
                    border-radius: 10px;
                }

                /* QTabWidget Styling */
                QTabWidget::pane {
                    border: 1px solid #444444;
                    background-color: #252526; /* Darker background for tab content */
                    border-radius: 8px;
                    padding: 10px;
                }

                QTabBar::tab {
                    background: #3C3C3C;
                    border: 1px solid #444444;
                    border-bottom-left-radius: 5px;
                    border-bottom-right-radius: 5px;
                    padding: 10px 20px;
                    margin-right: 2px;
                    color: #BBBBBB; /* Lighter gray for tab text */
                    font-weight: bold;
                }

                QTabBar::tab:selected {
                    background: #252526; /* Matches pane background */
                    border-color: #444444;
                    border-bottom-color: #252526; /* Make the selected tab's bottom border blend with the pane */
                    color: #FFFFFF; /* White text for selected tab */
                }

                QTabBar::tab:hover {
                    background: #4A4A4A; /* Slightly lighter dark gray on hover */
                }

                /* QLineEdit Styling */
                QLineEdit {
                    border: 1px solid #555555;
                    border-radius: 5px;
                    padding: 8px;
                    background-color: #333333; /* Dark background for input fields */
                    color: #E0E0E0; /* Light text color */
                    selection-background-color: #007ACC; /* VS Code blue for selection */
                }

                /* QTextEdit Styling */
                QTextEdit {
                    border: 1px solid #555555;
                    border-radius: 5px;
                    padding: 10px;
                    background-color: #333333; /* Dark background for text areas */
                    color: #E0E0E0; /* Light text color */
                    selection-background-color: #007ACC;
                }

                /* QPushButton Styling */
                QPushButton {
                    background-color: #007ACC; /* A prominent blue for buttons */
                    color: white;
                    border: none;
                    border-radius: 5px;
                    padding: 10px 15px;
                    font-weight: bold;
                    min-width: 100px;
                }

                QPushButton:hover {
                    background-color: #005F99; /* Darker blue on hover */
                }

                QPushButton:pressed {
                    background-color: #004C7A; /* Even darker blue when pressed */
                }

                QPushButton:disabled {
                    background-color: #555555;
                    color: #AAAAAA;
                }

                /* QLabel Styling */
                QLabel {
                    color: #E0E0E0; /* Light gray for labels */
                    font-weight: 500;
                }

                /* QCheckBox Styling */
                QCheckBox {
                    color: #E0E0E0;
                }
                QCheckBox::indicator {
                    width: 16px;
                    height: 16px;
                    border: 1px solid #555555;
                    border-radius: 3px;
                    background-color: #333333;
                }
                QCheckBox::indicator:checked {
                    background-color: #007ACC;
                    border: 1px solid #007ACC;
                    /* Base64 encoded SVG for a simple checkmark */
                    image: url(data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxNiIgaGVpZ2h0PSIxNiIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9IndoaXRlIiBzdHJva2Utd2lkdGg9IjMiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIgc3Ryb2tlLWxpbmVqb2luPSJyb3VuZCI+PHBvbHlsaW5lIHBvaW50cz0iMjAgNiA5IDE3IDQgMTIiPjwvcG9seWxpbmU+PC9zdmc+);
                }
                QCheckBox::indicator:disabled {
                    background-color: #444444;
                    border: 1px solid #666666;
                }

                /* QMessageBox Styling */
                QMessageBox {
                    background-color: #2B2B2B; /* Consistent with main app background */
                    font-size: 14px;
                    color: #E0E0E0;
                }
                QMessageBox QPushButton {
                    background-color: #007ACC;
                    color: white;
                    border-radius: 5px;
                    padding: 8px 15px;
                }
                QMessageBox QPushButton:hover {
                    background-color: #005F99;
                }
            """
        else:  # Light mode
            qss = """
                QWidget {
                    font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
                    font-size: 14px;
                    color: #333;
                    background-color: #f0f2f5; /* Light gray background */
                }

                /* Main Window */
                PIIAnalyzerApp {
                    background-color: #e0e2e5; /* Slightly darker background for the main window */
                    border-radius: 10px;
                }

                /* QTabWidget Styling */
                QTabWidget::pane {
                    border: 1px solid #c0c2c5;
                    background-color: #ffffff; /* White background for tab content */
                    border-radius: 8px;
                    padding: 10px;
                }

                QTabBar::tab {
                    background: #d0d2d5;
                    border: 1px solid #c0c2c5;
                    border-bottom-left-radius: 5px;
                    border-bottom-right-radius: 5px;
                    padding: 10px 20px;
                    margin-right: 2px;
                    color: #555;
                    font-weight: bold;
                }

                QTabBar::tab:selected {
                    background: #ffffff;
                    border-color: #c0c2c5;
                    border-bottom-color: #ffffff; /* Make the selected tab's bottom border blend with the pane */
                    color: #2c3e50;
                }

                QTabBar::tab:hover {
                    background: #e9ecef;
                }

                /* QLineEdit Styling */
                QLineEdit {
                    border: 1px solid #c0c2c5;
                    border-radius: 5px;
                    padding: 8px;
                    background-color: #ffffff;
                    selection-background-color: #a8d8ff;
                }

                /* QTextEdit Styling */
                QTextEdit {
                    border: 1px solid #c0c2c5;
                    border-radius: 5px;
                    padding: 10px;
                    background-color: #ffffff;
                    color: #333;
                    selection-background-color: #a8d8ff;
                }

                /* QPushButton Styling */
                QPushButton {
                    background-color: #007bff; /* Primary blue */
                    color: white;
                    border: none;
                    border-radius: 5px;
                    padding: 10px 15px;
                    font-weight: bold;
                    min-width: 100px;
                }

                QPushButton:hover {
                    background-color: #0056b3; /* Darker blue on hover */
                }

                QPushButton:pressed {
                    background-color: #004085; /* Even darker blue when pressed */
                }

                QPushButton:disabled {
                    background-color: #cccccc;
                    color: #666666;
                }

                /* QLabel Styling */
                QLabel {
                    color: #333;
                    font-weight: 500;
                }

                /* QCheckBox Styling */
                QCheckBox {
                    color: #333;
                }
                QCheckBox::indicator {
                    width: 16px;
                    height: 16px;
                    border: 1px solid #c0c2c5;
                    border-radius: 3px;
                    background-color: #ffffff;
                }
                QCheckBox::indicator:checked {
                    background-color: #007bff;
                    border: 1px solid #007bff;
                    /* Base64 encoded SVG for a simple checkmark */
                    image: url(data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxNiIgaGVpZ2h0PSIxNiIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9IndoaXRlIiBzdHJva2Utd2lkdGg9IjMiHN0cm9rZS1liW5lY2FwPSJyb3VuZCIgc3Ryb2tlLWxpbmVqb2luPSJyb3VuZCI+PHBvbHlsaW5lIHBvaW50cz0iMjAgNiA5IDE3IDQgMTIiPjwvcG9seWxpbmU+PC9zdmc+);
                }
                QCheckBox::indicator:disabled {
                    background-color: #e0e0e0;
                    border: 1px solid #b0b0b0;
                }

                /* QMessageBox Styling */
                QMessageBox {
                    background-color: #f0f2f5; /* Consistent with main app background */
                    font-size: 14px;
                    color: #333;
                }
                QMessageBox QPushButton {
                    background-color: #007bff;
                    color: white;
                    border-radius: 5px;
                    padding: 8px 15px;
                }
                QMessageBox QPushButton:hover {
                    background-color: #0056b3;
                }
            """
        self.setStyleSheet(qss)


# --- Main execution block ---
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PIIAnalyzerApp()
    window.show()
    sys.exit(app.exec_())

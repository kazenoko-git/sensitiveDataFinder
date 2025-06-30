import os
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, RecognizerResult
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
from typing import List, Dict, Optional

# --- Custom Recognizers for Passwords and Usernames ---

class PasswordRecognizer(PatternRecognizer):
    """
    A custom Presidio recognizer for detecting potential passwords based on keywords.
    This is a heuristic approach and prone to false positives/negatives.
    """
    PATTERNS = [
        # Look for "password:" or "pwd=" followed by at least 6 characters
        ("PASSWORD_KEYWORD",
         r"(?i)(password|pwd|pass|secret|api_key|token)[:=\s]*([a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?`~]{6,})",
         0.7),
        # Detect common password-like strings (e.g., "admin123", "password") - very high false positive risk
        # This regex is highly simplified and will catch many non-passwords. For demo.
        ("COMMON_PASSWORD_STRING", r"(?i)\b(password|admin|123456|qwerty)\b", 0.9)
    ]

    # Adding context words can improve accuracy
    CONTEXT = ["login", "credentials", "user", "access"]

    def __init__(self):
        super().__init__(supported_entity="PASSWORD", patterns=self.PATTERNS, context=self.CONTEXT)

    def analyze(self, text: str, entities: List[str] = None, language: str = "en") -> List[RecognizerResult]:
        """
        Overrides the analyze method to potentially extract the value after the keyword.
        """
        results = super().analyze(text, entities, language)

        # Post-process results to extract the actual "password" part
        final_results = []
        for res in results:
            if res.entity_type == "PASSWORD":
                # Find the full match from the regex pattern
                match = next((p.regex.search(text[res.start:res.end + 20]) for p in self.PATTERNS if
                              p.regex.search(text[res.start:res.end + 20])), None)
                if match and len(match.groups()) > 1:
                    # If the regex has a capturing group for the value
                    password_value = match.group(2)  # Assuming group 2 is the actual password
                    # Adjust end to cover the actual password value
                    res.end = res.start + len(match.group(0))  # Adjust end to cover the full match
                    res.text = match.group(0)  # Store the full matched text
                    final_results.append(res)
                else:
                    final_results.append(res)  # Keep original if no specific value extracted
        return final_results


class UsernameRecognizer(PatternRecognizer):
    """
    A custom Presidio recognizer for detecting potential usernames based on keywords.
    Also heuristic and prone to false positives/negatives.
    """
    PATTERNS = [
        ("USERNAME_KEYWORD", r"(?i)(username|user|login|id|account)[:=\s]*([a-zA-Z0-9._-]{3,})", 0.6),
        # Very general pattern for strings that might be usernames
        ("COMMON_USERNAME_PATTERN", r"\b[a-z][a-zA-Z0-9_.-]{3,20}\b", 0.4)  # Starts with letter, 3-20 chars
    ]
    CONTEXT = ["login", "credentials", "password", "id"]

    def __init__(self):
        super().__init__(supported_entity="USERNAME", patterns=self.PATTERNS, context=self.CONTEXT)

    def analyze(self, text: str, entities: List[str] = None, language: str = "en") -> List[RecognizerResult]:
        results = super().analyze(text, entities, language)
        final_results = []
        for res in results:
            if res.entity_type == "USERNAME":
                match = next((p.regex.search(text[res.start:res.end + 20]) for p in self.PATTERNS if
                              p.regex.search(text[res.start:res.end + 20])), None)
                if match and len(match.groups()) > 1:
                    username_value = match.group(2)
                    res.end = res.start + len(match.group(0))
                    res.text = match.group(0)
                    final_results.append(res)
                else:
                    final_results.append(res)
        return final_results


# --- Main Detection Logic with Presidio ---

def initialize_presidio_analyzer():
    """Initializes Presidio Analyzer with a large English model and custom recognizers."""
    analyzer = AnalyzerEngine(nlp_engine={"en": "spacy", "spacy_model_paths": {"en": "en_core_web_lg"}})

    # Add custom recognizers
    analyzer.registry.add_recognizer(PasswordRecognizer())
    analyzer.registry.add_recognizer(UsernameRecognizer())

    return analyzer


def find_sensitive_data_with_presidio(text_content: str, analyzer: AnalyzerEngine) -> Dict[str, List[Dict]]:
    """
    Scans the given text content for sensitive data using Presidio.
    Returns a dictionary of found sensitive data categories and their details.
    """
    sensitive_data_found = {}

    # Define entities to be detected explicitly for clarity.
    # Presidio's default recognizers cover many of these.
    # We add our custom ones: "PASSWORD", "USERNAME"
    entities_to_detect = [
        "PERSON",  # Names
        "PHONE_NUMBER",  # Phone numbers (various formats)
        "EMAIL_ADDRESS",  # Email addresses
        "CREDIT_CARD",  # Credit card numbers (with Luhn validation)
        "US_SSN",  # US Social Security Numbers
        "IP_ADDRESS",  # IP addresses (IPv4, IPv6)
        "LOCATION",  # Physical addresses, cities, countries
        "DATE_TIME",  # Dates and times
        "IBAN_CODE",  # International Bank Account Numbers
        "NRP",  # National identification numbers (e.g., Passport, Driver's License)
        "MEDICAL_LICENSE",  # Medical license numbers
        "US_DRIVER_LICENSE",  # US Driver's License
        "US_PASSPORT",  # US Passport
        "CRYPTO",  # Crypto wallet addresses (e.g., Bitcoin)
        "URL",  # URLs
        "FINANCIAL_ACCOUNT",  # Generic financial account numbers (less specific)
        # Custom entities
        "PASSWORD",  # Custom: Potential passwords
        "USERNAME"  # Custom: Potential usernames
    ]

    # Analyze the text to find PII entities
    results = analyzer.analyze(
        text=text_content,
        language='en',
        entities=entities_to_detect,  # Specify which entities to look for
        return_debug_artifacts=False  # Set to True for more detailed debug info
    )

    if results:
        for result in results:
            entity_type = result.entity_type
            if entity_type not in sensitive_data_found:
                sensitive_data_found[entity_type] = []

            # Store the detected entity text, start and end positions, and score
            sensitive_data_found[entity_type].append({
                "text": text_content[result.start:result.end],
                "start": result.start,
                "end": result.end,
                "score": result.score  # Confidence score from the detector
            })
    return sensitive_data_found


def scan_file_with_presidio(filepath: str, analyzer: AnalyzerEngine):
    """
    Reads a file and scans its content for sensitive data using Presidio.
    """
    print(f"\nScanning file: {filepath}")
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            found_data = find_sensitive_data_with_presidio(content, analyzer)

            found_data_filtered = {k: v for k, v in found_data.items() if v}

            if found_data_filtered:
                print("  Sensitive data found:")
                for category, items in found_data_filtered.items():
                    print(f"    - {category.replace('_', ' ').title()}:")
                    for item in items:
                        print(f"      * '{item['text']}' (Confidence: {item['score']:.2f})")
            else:
                print("  No sensitive data patterns found.")
    except Exception as e:
        print(f"  Error reading file {filepath}: {e}")


def scan_directory_with_presidio(directory_path: str, analyzer: AnalyzerEngine):
    """
    Scans all text-like files in a given directory and its subdirectories using Presidio.
    """
    print(f"Starting scan in directory: {directory_path}")
    for root, _, files in os.walk(directory_path):
        for file in files:
            # You can customize file extensions to scan
            if file.endswith(('.txt', '.log', '.csv', '.json', '.xml', '.html', '.py', '.md', '.yml', '.ini')):
                filepath = os.path.join(root, file)
                scan_file_with_presidio(filepath, analyzer)
            else:
                print(f"Skipping non-text file: {file}")


def anonymize_text_with_presidio(text_content: str, analyzer: AnalyzerEngine) -> str:
    """
    Anonymizes sensitive data in the given text content using Presidio.
    """
    anonymizer = AnonymizerEngine()

    # Re-analyze with the full set of entities, including custom ones, for anonymization
    results = analyzer.analyze(
        text=text_content,
        language='en',
        entities=[
            "PERSON", "PHONE_NUMBER", "EMAIL_ADDRESS", "CREDIT_CARD", "US_SSN",
            "IP_ADDRESS", "LOCATION", "DATE_TIME", "IBAN_CODE", "NRP",
            "MEDICAL_LICENSE", "US_DRIVER_LICENSE", "US_PASSPORT", "CRYPTO", "URL",
            "FINANCIAL_ACCOUNT", "PASSWORD", "USERNAME"  # Include custom entities
        ]
    )

    # Define custom operators for anonymization.
    # Default is 'replace' with "<{entity_type}>".
    # We can be more specific for some types.
    anonymized_text = anonymizer.anonymize(
        text=text_content,
        analyzer_results=results,
        operators={
            "DEFAULT": OperatorConfig("replace", {"new_value": "<{entity_type}>"}),
            "CREDIT_CARD": OperatorConfig("mask", {"masking_char": "*", "chars_to_mask": 4, "from_end": True}),
            "US_SSN": OperatorConfig("mask", {"masking_char": "*", "chars_to_mask": 4, "from_end": True}),
            "PHONE_NUMBER": OperatorConfig("mask", {"masking_char": "*", "chars_to_mask": 4, "from_end": True}),
            "PASSWORD": OperatorConfig("replace", {"new_value": "<PASSWORD_REDACTED>"}),  # Custom redaction
            "USERNAME": OperatorConfig("replace", {"new_value": "<USERNAME_REDACTED>"}),  # Custom redaction
            "IP_ADDRESS": OperatorConfig("mask", {"masking_char": "*", "chars_to_mask": 6, "from_end": False}),
            # Mask first few chars
            "URL": OperatorConfig("replace", {"new_value": "<URL_REDACTED>"})
        }
    )
    return anonymized_text.text


if __name__ == "__main__":
    # Initialize Presidio Analyzer once
    print("Initializing Presidio Analyzer (may take a moment to load NLP models and custom recognizers)...")
    presidio_analyzer = initialize_presidio_analyzer()
    print("Presidio Analyzer initialized.")

    # --- Example Usage ---

    # 1. Scan a single string
    print("\n--- Scanning a single string (with Presidio and custom detectors) ---")
    test_string_presidio = """
    Hello, my email is test@example.com and my phone number is +91 98765-43210.
    My name is John Doe and I live at 1600 Amphitheatre Parkway, Mountain View, CA 94043.
    Another email: alice.smith@corp.co.uk. Call me at 080-1234-5678.
    My credit card is 1234-5678-9012-3456. My IP address is 192.168.1.1.
    Here's another CC: 4444555566667777 and my SSN is 111-22-3333.
    Dr. Jane Miller works at Acme Corp. and her medical license is ML-12345.
    Passport: US123456789. Driver's License: DL-CA-987654.
    An IBAN code: DE89370400440532013000. Bitcoin address: 1BvBMSEYstWetqTFn5Au4m4GFp4z5Etr4.
    Visit my website at https://www.mysensitiveinfo.com.
    Login with username: superuser and password: MyStrongPass!@#123
    Another user: dev_ops with token=ghp_ABCDEFGHIJKLMN
    API_KEY=xyz_123_abc_456
    """
    results_presidio = find_sensitive_data_with_presidio(test_string_presidio, presidio_analyzer)

    results_filtered_presidio = {k: v for k, v in results_presidio.items() if v}
    if results_filtered_presidio:
        print("Sensitive data found in string:")
        for category, items in results_filtered_presidio.items():
            print(f"  - {category.replace('_', ' ').title()}:")
            for item in items:
                print(f"      * '{item['text']}' (Confidence: {item['score']:.2f})")
    else:
        print("No sensitive data patterns found in string.")

    # 2. Anonymize the string
    print("\n--- Anonymizing the string (with Presidio) ---")
    anonymized_text = anonymize_text_with_presidio(test_string_presidio, presidio_analyzer)
    print("Original text:\n", test_string_presidio)
    print("\nAnonymized text:\n", anonymized_text)

    # 3. Create some dummy files for directory scanning
    print("\n--- Creating dummy files for directory scan (with Presidio) ---")
    temp_dir_presidio = "temp_data_presidio_ai"
    if not os.path.exists(temp_dir_presidio):
        os.makedirs(temp_dir_presidio)
    if not os.path.exists(os.path.join(temp_dir_presidio, "sub_dir")):
        os.makedirs(os.path.join(temp_dir_presidio, "sub_dir"))

    with open(os.path.join(temp_dir_presidio, "log_data.log"), "w") as f:
        f.write("Contact us at support@example.co.in or +91-88888-77777.\n")
        f.write("Our old card was 9876 5432 1098 7654. New account: 1111222233334444.\n")
        f.write("Internal IP: 10.0.0.100. External: 203.0.113.45.\n")
        f.write(
            "My SSN is 999-88-7777. The patient's name is Sarah Connor. She lives at 789 Oak Ave, Springfield, IL.\n")
        f.write("User: jane.doe, PWD=secret_admin_password.\n")

    with open(os.path.join(temp_dir_presidio, "config.ini"), "w") as f:
        f.write("[Settings]\n")
        f.write("DB_HOST=localhost\n")
        f.write("DB_USER=root\n")
        f.write("DB_PASSWORD=my_db_pwd\n")
        f.write("ADMIN_EMAIL=admin@internal.net\n")
        f.write("API_TOKEN=token_xyz_789_pqr\n")

    print(f"Dummy files created in '{temp_dir_presidio}' directory.")

    # 4. Scan a directory
    print(f"\n--- Scanning '{temp_dir_presidio}' directory ---")
    scan_directory_with_presidio(temp_dir_presidio, presidio_analyzer)

    # Clean up dummy files
    import shutil

    print("\n--- Cleaning up dummy files ---")
    shutil.rmtree(temp_dir_presidio)
    print(f"'{temp_dir_presidio}' directory removed.")
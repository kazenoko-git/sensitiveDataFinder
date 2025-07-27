from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine, OperatorConfig
import fileHandler as fH
from groq import Groq
import spacy

with open("settings.txt", "r") as f: dt = str(f.read()).split(';')
key = rf'{dt[2].split("=")[1]}'

class CHK:
    def __init__(self):
        try:
            spacy.load("en_core_web_lg")
            print("spaCy model 'en_core_web_lg' found.")
        except OSError:
            print("spaCy model 'en_core_web_lg' not found. Attempting to download...")
            try:
                spacy.cli.download("en_core_web_lg")
                print("spaCy model 'en_core_web_lg' downloaded successfully.")
            except Exception as e:
                print(f"Error downloading spaCy model: {e}")
                print("Please try running 'python -m spacy download en_core_web_lg' manually from your terminal.")
                # Depending on severity, you might want to sys.exit(1) here
            # --- End: Fix for spaCy model not found ---

        configuration = {
            "nlp_engine_name": "spacy",
            "models": [
                {"lang_code": "en", "model_name": "en_core_web_lg"},
            ],
        }
        self.pilot = Groq(api_key=key)
        self.memory = [{"role": "system", "content": """You are a highly accurate PII classification assistant. Your task is to determine if the provided text is a real-world, identifiable instance of the specified sensitive data type, *not* just a string that happens to match a pattern in a technical context (like a configuration value, a random ID, a common word, or a code snippet). Respond with only one word: 'True' if it is a real-world PII, or 'False' if it is not. Do not provide any other text or explanation.

Examples:
- Is the text 'john.doe@example.com' a real-world example of an 'EMAIL_ADDRESS'? Answer True.
- Is the text '123-abc-456' a real-world example of a 'PHONE_NUMBER'? Answer False.
- Is the text 'password123' a real-world example of a 'PASSWORD'? Answer True.
- Is the text 'leftFreq":20.0' a real-world example of a 'PASSWORD'? Answer False.
- Is the text 'at' a real-world example of a 'PERSON'? Answer False.
- Is the text 'frequency":117.11509134647333' a real-world example of a 'PHONE_NUMBER'? Answer False.
- Is the text 'colorId":4' a real-world example of a 'PERSON'? Answer False.
- Is the text 'ssh-rsa AAAAB3NzaC...' a real-world example of an 'SSH_KEY'? Answer True.
- Is the text '1234 5678 9012' a real-world example of an 'AADHAAR_NUMBER'? Answer True.
- Is the text 'ABCDE1234F' a real-world example of a 'PAN_NUMBER'? Answer True.
- Is the text 'sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' a real-world example of an 'API_KEY'? Answer True.
- Is the text 'my_variable_key' a real-world example of an 'API_KEY'? Answer False.
"""}]

        # Initialize Presidio Analyzer and Anonymizer
        provider = NlpEngineProvider(nlp_configuration=configuration)
        nlp_engine = provider.create_engine()
        self.analyzer = AnalyzerEngine(nlp_engine=nlp_engine)
        self.anonymizer = AnonymizerEngine()

        # Custom regex patterns for better detection
        password_pattern = Pattern(
            name="password_pattern",
            regex=r"\b(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z0-9!@#$%^&*()_+=\-\[\]{}|;:'\",.<>\/?`~]{8,}\b",
            score=0.95
        )
        ssn_pattern = Pattern(
            name="ssn_pattern",
            regex=r"\b\d{3}-\d{2}-\d{4}\b",
            score=0.9
        )
        phone_pattern = Pattern(
            name="phone_pattern",
            regex=r"\b(?:\+?(\d{1,3}))?[-. (]*(\d{3})[-. )]*(\d{3})[-. ]*(\d{4})(?: *x(\d+))?\b",
            score=0.9
        )
        address_pattern = Pattern(
            name="address_pattern",
            regex=r"\b\d{1,5}\s(?:[A-Za-z0-9\s\.,'#-]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Place|Pl|Square|Sq|Terrace|Ter|Parkway|Pkwy|Circle|Cir)\.?)[\s,]+[A-Za-z\s\.,'-]+,\s*[A-Z]{2}\s*\d{5}(?:-\d{4})?\b",
            score=0.85
        )
        # SSH Key pattern
        ssh_key_pattern = Pattern(
            name="ssh_key_pattern",
            regex=r"ssh-(rsa|dss|ecdsa|ed25519)\s[A-Za-z0-9+/=]+\s*.*",
            score=0.95
        )
        # AADHAAR Number pattern (12 digits, often in groups of 4)
        aadhaar_pattern = Pattern(
            name="aadhaar_pattern",
            regex=r"\b\d{4}\s\d{4}\s\d{4}\b|\b\d{12}\b",
            score=0.9
        )
        # PAN Card pattern (5 letters, 4 digits, 1 letter)
        pan_pattern = Pattern(
            name="pan_pattern",
            regex=r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b",
            score=0.9
        )
        # This pattern looks for common prefixes like 'sk-', 'AKIA', 'SG.', 'pk_', 'Bearer ' followed by alphanumeric characters and symbols.
        api_key_pattern = Pattern(
            name="api_key_pattern",
            regex=r"\b(?:sk-|AKIA|SG\.|pk_|Bearer\s|xoxb-|EAACEdEose|ya29\.[a-zA-Z0-9_-]+|AIza[0-9A-Za-z-_]{35}|[A-Za-z0-9-_]{20,40}(?:\.[A-Za-z0-9-_]{20,40})?)\b",
            score=0.85
        )

        # Add custom recognizers to the analyzer engine
        password_recognizer = PatternRecognizer(
            supported_entity="PASSWORD",
            patterns=[password_pattern]
        )
        ssn_recognizer = PatternRecognizer(
            supported_entity="US_SSN",
            patterns=[ssn_pattern]
        )
        phone_recognizer = PatternRecognizer(
            supported_entity="PHONE_NUMBER",
            patterns=[phone_pattern]
        )
        address_recognizer = PatternRecognizer(
            supported_entity="ADDRESS",
            patterns=[address_pattern]
        )
        ssh_key_recognizer = PatternRecognizer(
            supported_entity="SSH_KEY",
            patterns=[ssh_key_pattern]
        )
        aadhaar_recognizer = PatternRecognizer(
            supported_entity="AADHAAR_NUMBER",
            patterns=[aadhaar_pattern]
        )
        pan_recognizer = PatternRecognizer(
            supported_entity="PAN_NUMBER",
            patterns=[pan_pattern]
        )
        # NEW: API Key recognizer
        api_key_recognizer = PatternRecognizer(
            supported_entity="API_KEY",
            patterns=[api_key_pattern]
        )

        self.analyzer.registry.add_recognizer(password_recognizer)
        self.analyzer.registry.add_recognizer(ssn_recognizer)
        self.analyzer.registry.add_recognizer(phone_recognizer)
        self.analyzer.registry.add_recognizer(address_recognizer)
        self.analyzer.registry.add_recognizer(ssh_key_recognizer)
        self.analyzer.registry.add_recognizer(aadhaar_recognizer)
        self.analyzer.registry.add_recognizer(pan_recognizer)
        self.analyzer.registry.add_recognizer(api_key_recognizer)

        self.analysis = []
        self.anonymizedData = []

    # Modified check method to accept enable_groq_recheck flag
    def check(self, indir, enable_groq_recheck: bool = False) -> list:
        """
        Analyzes and anonymizes sensitive data from the input directory.

        Args:
            indir (str): The input directory or path (used by mock fileHandler).
            enable_groq_recheck (bool): Flag to enable/disable Groq rechecking.

        Returns:
            list: A list containing two lists:
                  - self.analysis: Details of detected entities (type, value, score).
                  - self.anonymizedData: The anonymized versions of the input texts.
        """
        # Get data using the fileHandler
        sample_full_texts = fH.get_data(rf"{indir}")
        print(f"\n--- Starting PII Analysis for {len(sample_full_texts)} items ---")

        # Define the Groq generation function with retry logic
        def gen(dt, data, retries=3) -> str:
            temp_memory = list(self.memory)
            # Refined user prompt for better filtering
            temp_memory.append({"role": "user",
                                "content": f"Is the text '{data}' a real-world example of a '{dt}'? Answer True or False."})

            for attempt in range(retries):
                try:
                    res_obj = self.pilot.chat.completions.create(model="llama3-70b-8192", messages=temp_memory,
                                                                 max_tokens=8)
                    res_text = res_obj.choices[0].message.content.strip()
                    print(f"  [Groq Check] '{dt}' for '{data}' -> Response: '{res_text}' (Attempt {attempt + 1})")

                    if res_text.lower() == "true":
                        return "True"
                    else:  # Treat anything not explicitly "true" as "false" for filtering purposes
                        print(f"  [Groq Check] '{dt}' for '{data}' -> Response: '{res_text}'. Treating as False.")
                        return "False"
                except Exception as e:
                    print(f"  [Error] Failed to call Groq API for '{dt}' on '{data}': {e} (Attempt {attempt + 1})")
                    if attempt == retries - 1:
                        return "False"  # Return False after all retries if API fails
            return "False"  # Should not be reached if retries are handled correctly

        # Clear previous results before processing new data
        self.analysis = []
        self.anonymizedData = []

        # Iterate through each full text content from the files
        for item_text in sample_full_texts:
            print(f"\n--- Analyzing Text: '{item_text}' ---")

            # Analyze the text for sensitive entities
            results = self.analyzer.analyze(
                text=item_text,
                language="en",
                entities=["EMAIL_ADDRESS", "CREDIT_CARD", "PHONE_NUMBER", "US_SSN", "PERSON", "ADDRESS", "PASSWORD",
                          "SSH_KEY", "AADHAAR_NUMBER", "PAN_NUMBER", "API_KEY"],
                return_decision_process=True
            )

            filtered_results = []
            current_item_analysis_entries = []

            for result in results:
                entity_value = item_text[result.start:result.end]
                analysis_entry = f"{result.entity_type}={entity_value}:{result.score}"

                if enable_groq_recheck:
                    print(f"  Performing Groq recheck for: {analysis_entry}")
                    res = gen(result.entity_type, entity_value)

                    if res.lower() == "true":
                        # Only add if Groq confirms AND score is high enough (if you still want this threshold)
                        if result.score >= 0.8:
                            filtered_results.append(result)
                            current_item_analysis_entries.append(f"{analysis_entry} (Groq Confirmed)")
                        else:
                            print(f"    - Groq confirmed, but score is too low ({result.score}). Skipping.")
                    elif res.lower() == "false":
                        print(f"    - Groq explicitly denied '{result.entity_type}' for '{entity_value}'. Skipping.")
                    # No 'else' block here, as gen() now always returns 'True' or 'False'
                else:
                    # If Groq recheck is disabled, just use Presidio's results
                    filtered_results.append(result)
                    current_item_analysis_entries.append(analysis_entry)

            # Anonymize using the filtered results
            anonymized_result = self.anonymizer.anonymize(
                text=item_text,
                analyzer_results=filtered_results,  # Use filtered results for anonymization
                operators={
                    "PERSON": OperatorConfig("replace", {"type": "replace", "new_value": "[REDACTED]"}),
                    "EMAIL_ADDRESS": OperatorConfig("mask", {"type": "mask", "masking_char": "*", "chars_to_mask": 10,
                                                             "from_end": False}),
                    "CREDIT_CARD": OperatorConfig("mask", {"type": "mask", "masking_char": "*", "chars_to_mask": 12,
                                                           "from_end": False}),
                    "PHONE_NUMBER": OperatorConfig("mask", {"type": "mask", "masking_char": "*", "chars_to_mask": 7,
                                                            "from_end": False}),
                    "US_SSN": OperatorConfig("mask", {"type": "mask", "masking_char": "*", "chars_to_mask": 7,
                                                      "from_end": False}),
                    "ADDRESS": OperatorConfig("replace", {"type": "replace", "new_value": "[REDACTED]"}),
                    "PASSWORD": OperatorConfig("replace", {"type": "replace", "new_value": "[REDACTED]"}),
                    "SSH_KEY": OperatorConfig("replace", {"type": "replace", "new_value": "[SSH_KEY_REDACTED]"}),
                    "AADHAAR_NUMBER": OperatorConfig("mask", {"type": "mask", "masking_char": "X", "chars_to_mask": 8,
                                                              "from_end": False}),
                    "PAN_NUMBER": OperatorConfig("mask", {"type": "mask", "masking_char": "X", "chars_to_mask": 6,
                                                          "from_end": False}),
                    "API_KEY": OperatorConfig("replace", {"type": "replace", "new_value": "[API_KEY_REDACTED]"})  # NEW
                }
            )

            # Add all entries for this item (including those filtered by Groq if applicable)
            self.analysis.extend(current_item_analysis_entries)
            # Append the full anonymized text for this item
            self.anonymizedData.append(anonymized_result.text)
            print(f"  Anonymized Text: '{anonymized_result.text}'")

        print("\n--- All Analysis Results ---")
        for entry in self.analysis:
            print(entry)

        print("\n--- All Anonymized Data ---")
        for entry in self.anonymizedData:
            print(entry)

        return [self.analysis, self.anonymizedData]


# Test

"""
if __name__ == "__main__":
    a = chk()
    # Example usage with Groq recheck enabled/disabled
    # The path here is used by the mock fileHandler.py.
    # In a real scenario, ensure it points to your actual input file.

    # Create a dummy directory and files for testing if they don't exist
    test_dir = "test_data_combined"
    os.makedirs(test_dir, exist_ok=True)

    with open(os.path.join(test_dir, "test_pii.txt"), "w", encoding="utf-8") as f:
        f.write(
            "My email is test@example.com and my phone is +91-9876543210. My SSN is 123-45-6789. John Doe lives at 123 Main St, Anytown, CA 90210. My password is StrongP@ss1. Here's an SSH key: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCw0+... user@host. My AADHAAR is 1234 5678 9012. My PAN is ABCDE1234F. My API key is sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.")

    with open(os.path.join(test_dir, "config.ini"), "w", encoding="utf-8") as f:
        f.write("[settings]\npassword=mysecret\nfreq=20.0\ncolorId=4\napi_key=some_internal_key_value")

    print("\n--- Running with Groq Recheck ENABLED ---")
    final_output_groq_enabled = a.check(test_dir, enable_groq_recheck=True)
    print("\nFinal Return Value from check() method (Groq Enabled):")
    print("Aggregated Analysis Results:")
    for item in final_output_groq_enabled[0]:
        print(f"  {item}")
    print("\nAggregated Anonymized Data:")
    for item in final_output_groq_enabled[1]:
        print(f"  {item}")

    print("\n--- Running with Groq Recheck DISABLED ---")
    final_output_groq_disabled = a.check(test_dir, enable_groq_recheck=False)
    print("\nFinal Return Value from check() method (Groq Disabled):")
    print("Aggregated Analysis Results:")
    for item in final_output_groq_disabled[0]:
        print(f"  {item}")
    print("\nAggregated Anonymized Data:")
    for item in final_output_groq_disabled[1]:
        print(f"  {item}")

    # Clean up dummy directory
    import shutil

    if os.path.exists(test_dir):
        shutil.rmtree(test_dir)
        print(f"\nCleaned up {test_dir}")

"""

from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine, OperatorConfig
import fileHandler as fH   
from groq import Groq
import spacy
import os

with open("settings.txt", "r") as f:
    dt = str(f.read()).split(';')
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

        provider = NlpEngineProvider(nlp_configuration=configuration)
        nlp_engine = provider.create_engine()
        self.analyzer = AnalyzerEngine(nlp_engine=nlp_engine)
        self.anonymizer = AnonymizerEngine()

        # ---- Regex improvements ----
        credit_card_pattern = Pattern(
            name="credit_card_pattern",
            # Visa, MasterCard, Amex, Discover, JCB; excludes phone formats and phone-number delimiters
            regex=r"\b(?:4[0-9]{12}(?:[0-9]{3})?"         # Visa
                   r"|5[1-5][0-9]{14}"                    # MasterCard
                   r"|3[47][0-9]{13}"                     # American Express
                   r"|6(?:011|5[0-9]{2})[0-9]{12}"        # Discover, etc
                   r")\b",
            score=0.95
        )
        phone_pattern = Pattern(
            name="phone_pattern",
            # US/International phone, but will *not* match 14+ contiguous digits (those are likely CC)
            regex=r"\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b(?!\d)",
            score=0.9
        )
        email_pattern = Pattern(
            name="email_pattern",
            # Boundaries are strict so that only real emails, not "foo@var" code, match
            regex=r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
            score=0.96
        )
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
        address_pattern = Pattern(
            name="address_pattern",
            regex=r"\b\d{1,5}\s(?:[A-Za-z0-9\s\.,'#-]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Place|Pl|Square|Sq|Terrace|Ter|Parkway|Pkwy|Circle|Cir)\.?)[\s,]+[A-Za-z\s\.,'-]+,\s*[A-Z]{2}\s*\d{5}(?:-\d{4})?\b",
            score=0.85
        )
        ssh_key_pattern = Pattern(
            name="ssh_key_pattern",
            regex=r"ssh-(rsa|dss|ecdsa|ed25519)\s[A-Za-z0-9+/=]+\s*.*",
            score=0.95
        )
        aadhaar_pattern = Pattern(
            name="aadhaar_pattern",
            regex=r"\b\d{4}\s\d{4}\s\d{4}\b|\b\d{12}\b",
            score=0.9
        )
        pan_pattern = Pattern(
            name="pan_pattern",
            regex=r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b",
            score=0.9
        )
        api_key_pattern = Pattern(
            name="api_key_pattern",
            regex=r"\b(?:sk-|AKIA|SG\.|pk_|Bearer\s|xoxb-|EAACEdEose|ya29\.[a-zA-Z0-9_-]+|AIza[0-9A-Za-z-_]{35}|[A-Za-z0-9-_]{20,40}(?:\.[A-Za-z0-9-_]{20,40})?)\b",
            score=0.85
        )

        # ---- Custom recognizer registration ----
        self.analyzer.registry.add_recognizer(PatternRecognizer(
            supported_entity="CREDIT_CARD",
            patterns=[credit_card_pattern]
        ))
        self.analyzer.registry.add_recognizer(PatternRecognizer(
            supported_entity="PHONE_NUMBER",
            patterns=[phone_pattern]
        ))
        self.analyzer.registry.add_recognizer(PatternRecognizer(
            supported_entity="EMAIL_ADDRESS",
            patterns=[email_pattern]
        ))
        self.analyzer.registry.add_recognizer(PatternRecognizer(
            supported_entity="PASSWORD",
            patterns=[password_pattern]
        ))
        self.analyzer.registry.add_recognizer(PatternRecognizer(
            supported_entity="US_SSN",
            patterns=[ssn_pattern]
        ))
        self.analyzer.registry.add_recognizer(PatternRecognizer(
            supported_entity="ADDRESS",
            patterns=[address_pattern]
        ))
        self.analyzer.registry.add_recognizer(PatternRecognizer(
            supported_entity="SSH_KEY",
            patterns=[ssh_key_pattern]
        ))
        self.analyzer.registry.add_recognizer(PatternRecognizer(
            supported_entity="AADHAAR_NUMBER",
            patterns=[aadhaar_pattern]
        ))
        self.analyzer.registry.add_recognizer(PatternRecognizer(
            supported_entity="PAN_NUMBER",
            patterns=[pan_pattern]
        ))
        self.analyzer.registry.add_recognizer(PatternRecognizer(
            supported_entity="API_KEY",
            patterns=[api_key_pattern]
        ))

        self.analysis = []
        self.anonymizedData = []

    def check(self, indir, enable_groq_recheck: bool = False, scrub_files: bool = True, create_backup: bool = True, append_to_files=False) -> dict:
        """
        Analyzes, anonymizes, and (optionally) overwrites sensitive data in files from the input directory.

        Args:
            indir (str): The input directory or path (used by improved fileHandler).
            enable_groq_recheck (bool): Use LLM for semantic PII filtering.
            scrub_files (bool): If True, scrub detected PII from each source text file.
            create_backup (bool): If True, create a .backup before overwriting files.

        Returns:
            dict:
                {
                    'analysis': [...],
                    'anonymized_data': [...],
                    'scrub_summary': {...}  # Only present if scrub_files is True
                }
        """
        sample_full_texts = []
        file_paths = []
        # Use improved get_data_with_paths so we know [ (filepath, text), ... ]
        try:
            for item in fH.get_data_with_paths(indir):
                if not (isinstance(item, tuple) and len(item) == 2):
                    print(f"Unexpected item from get_data_with_paths: {item}")
                    continue
                path, text = item
                file_paths.append(path)
                sample_full_texts.append(text)
        except Exception as e:
            print("Error while iterating files:", e)
        print(f"\n--- Starting PII Analysis for {len(sample_full_texts)} items ---")

        def gen(dt, data, retries=3) -> str:
            temp_memory = list(self.memory)
            temp_memory.append({"role": "user", "content": f"Is the text '{data}' a real-world example of a '{dt}'? Answer True or False."})
            for attempt in range(retries):
                try:
                    res_obj = self.pilot.chat.completions.create(model="llama3-70b-8192", messages=temp_memory, max_tokens=8)
                    res_text = res_obj.choices[0].message.content.strip()
                    print(f"  [Groq Check] '{dt}' for '{data}' -> Response: '{res_text}' (Attempt {attempt + 1})")
                    if res_text.lower() == "true":
                        return "True"
                    print(f"  [Groq Check] '{dt}' for '{data}' -> Response: '{res_text}'. Treating as False.")
                    return "False"
                except Exception as e:
                    print(f"  [Error] Failed to call Groq API for '{dt}' on '{data}': {e} (Attempt {attempt + 1})")
                    if attempt == retries - 1:
                        return "False"
            return "False"

        self.analysis = []
        self.anonymizedData = []
        anonymized_per_file = []

        for idx, item_text in enumerate(sample_full_texts):
            print(f"\n--- Analyzing File: '{file_paths[idx]}' ---")
            results = self.analyzer.analyze(
                text=item_text,
                language="en",
                entities=[
                    "EMAIL_ADDRESS", "CREDIT_CARD", "PHONE_NUMBER", "US_SSN", "PERSON",
                    "ADDRESS", "PASSWORD", "SSH_KEY", "AADHAAR_NUMBER", "PAN_NUMBER", "API_KEY"
                ],
                return_decision_process=True
            )
            filtered_results = []
            analysis_entries = []

            for result in results:
                entity_value = item_text[result.start:result.end]
                analysis_entry = f"{result.entity_type}={entity_value}:{result.score}"
                if enable_groq_recheck:
                    print(f"  Performing Groq recheck for: {analysis_entry}")
                    res = gen(result.entity_type, entity_value)
                    if res.lower() == "true":
                        if result.score >= 0.8:
                            filtered_results.append(result)
                            analysis_entries.append(f"{analysis_entry} (Groq Confirmed)")
                        else:
                            print(f"    - Groq confirmed, but score is too low ({result.score}). Skipping.")
                    else:
                        print(f"    - Groq denied '{result.entity_type}' for '{entity_value}'. Skipping.")
                else:
                    filtered_results.append(result)
                    analysis_entries.append(analysis_entry)

            anonymized_result = self.anonymizer.anonymize(
                text=item_text,
                analyzer_results=filtered_results,
                operators={
                    "PERSON": OperatorConfig("replace", {"type": "replace", "new_value": "[REDACTED]"}),
                    "EMAIL_ADDRESS": OperatorConfig("mask", {"type": "mask", "masking_char": "*", "chars_to_mask": 10, "from_end": False}),
                    "CREDIT_CARD": OperatorConfig("mask", {"type": "mask", "masking_char": "*", "chars_to_mask": 12, "from_end": False}),
                    "PHONE_NUMBER": OperatorConfig("mask", {"type": "mask", "masking_char": "*", "chars_to_mask": 7, "from_end": False}),
                    "US_SSN": OperatorConfig("mask", {"type": "mask", "masking_char": "*", "chars_to_mask": 7, "from_end": False}),
                    "ADDRESS": OperatorConfig("replace", {"type": "replace", "new_value": "[REDACTED]"}),
                    "PASSWORD": OperatorConfig("replace", {"type": "replace", "new_value": "[REDACTED]"}),
                    "SSH_KEY": OperatorConfig("replace", {"type": "replace", "new_value": "[SSH_KEY_REDACTED]"}),
                    "AADHAAR_NUMBER": OperatorConfig("mask", {"type": "mask", "masking_char": "X", "chars_to_mask": 8, "from_end": False}),
                    "PAN_NUMBER": OperatorConfig("mask", {"type": "mask", "masking_char": "X", "chars_to_mask": 6, "from_end": False}),
                    "API_KEY": OperatorConfig("replace", {"type": "replace", "new_value": "[API_KEY_REDACTED]"}),
                }
            )
            self.analysis.extend(analysis_entries)
            self.anonymizedData.append(anonymized_result.text)
            anonymized_per_file.append(anonymized_result.text)
            print(f"  Anonymized Text: '{anonymized_result.text}'")

        # --- File scrubbing section ---
        if scrub_files:
            scrub_summary = fH.modify_files_remove_pii(
                input_source=indir,
                anonymized_results=anonymized_per_file,
                create_backup=create_backup,
                append=append_to_files,
            )
        return {
            "analysis": self.analysis,
            "anonymized_data": self.anonymizedData,
            "scrub_summary": scrub_summary if scrub_files else None,
        }

# -------------------------- USAGE -----------------------------------
"""
if __name__ == "__main__":
    a = CHK()
    test_dir = "test_data_combined"
    os.makedirs(test_dir, exist_ok=True)

    with open(os.path.join(test_dir, "test_pii.txt"), "w", encoding="utf-8") as f:
        f.write("My email is test@example.com and my phone is +91-9876543210. My SSN is 123-45-6789. John Doe lives at 123 Main St, Anytown, CA 90210. My password is StrongP@ss1. Here's an SSH key: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCw0+... user@host. My AADHAAR is 1234 5678 9012. My PAN is ABCDE1234F. My API key is sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.")

    with open(os.path.join(test_dir, "config.ini"), "w", encoding="utf-8") as f:
        f.write("[settings]\npassword=mysecret\nfreq=20.0\ncolorId=4\napi_key=some_internal_key_value")

    print("\n--- Running with Groq Recheck ENABLED, File Scrubbing ENABLED ---")
    result = a.check(test_dir, enable_groq_recheck=True, scrub_files=True, create_backup=True)
    print("\nReturn Value from check():")
    from pprint import pprint
    pprint(result)

    print("\n--- Check main test data files are redacted ---")
    with open(os.path.join(test_dir, "test_pii.txt")) as f:
        print(f.read())

    # Clean up dummy directory
    import shutil
    if os.path.exists(test_dir):
        shutil.rmtree(test_dir)
"""

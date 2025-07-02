from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine, OperatorConfig
import fileHandler as fH  
from groq import Groq
import os  


class chk:
    def __init__(self):
        key = os.environ['AI']

        configuration = {
            "nlp_engine_name": "spacy",
            "models": [
                {"lang_code": "en", "model_name": "en_core_web_lg"},
            ],
        }
        self.pilot = Groq(api_key=key)

        # Initialize memory for Groq. This will be used for the one-word True/False check.
        self.memory = [{"role": "system",
                        "content": "You are supposed to give a response in one word. Either False or True. You should check if the given data is the same as the given type of data. If the given data is same as type -> Answer is True, Else False. For example, <type_of_sensitive_data>:<data>. Or, another example: is <sensitive_data_type> ~= <data>?"}]

        # Initialize Presidio Analyzer and Anonymizer
        provider = NlpEngineProvider(nlp_configuration=configuration)
        nlp_engine = provider.create_engine()
        self.analyzer = AnalyzerEngine(nlp_engine=nlp_engine)
        self.anonymizer = AnonymizerEngine()

        # Custom regex patterns for better detection
        # UPDATED: Improved password pattern to correctly capture the password string.
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
        # This regex for address is quite specific and might miss many valid addresses.
        # A more robust address detection often requires more complex NLP or gazetteers.
        address_pattern = Pattern(
            name="address_pattern",
            regex=r"\b\d{1,5}\s(?:[A-Za-z0-9\s\.,'#-]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Place|Pl|Square|Sq|Terrace|Ter|Parkway|Pkwy|Circle|Cir)\.?)[\s,]+[A-Za-z\s\.,'-]+,\s*[A-Z]{2}\s*\d{5}(?:-\d{4})?\b",
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

        self.analyzer.registry.add_recognizer(password_recognizer)
        self.analyzer.registry.add_recognizer(ssn_recognizer)
        self.analyzer.registry.add_recognizer(phone_recognizer)
        self.analyzer.registry.add_recognizer(address_recognizer)

        # These lists will store the aggregated results from the check method
        self.analysis = []
        self.anonymizedData = []


    def check(self, indir,enable_groq_recheck: bool = False) -> list:
            """
            Analyzes and anonymizes sensitive data from the input directory.

            Args:
                indir (str): The input directory or path (used by mock fileHandler).

            Returns:
                list: A list containing two lists:
                      - self.analysis: Details of detected entities (type, value, score).
                      - self.anonymizedData: The anonymized versions of the input texts.
            """
            sample = fH.get_data(rf"{indir}")  # Get data using the fileHandler
            print(f"\n--- Starting PII Analysis for {len(sample)} items ---")

            # Define the Groq generation function. This function is currently commented
            # out in the main loop, but is fixed here for future use.
            def gen(dt, data) -> str:
                # Create a temporary copy of memory to avoid modifying self.memory for this specific call
                temp_memory = list(self.memory)
                temp_memory.append({"role": "user", "content": f"is {dt} ~= {data}?"})

                try:
                    # Call Groq API and correctly parse the response to get the text content
                    res_obj = self.pilot.chat.completions.create(model="llama3-70b-8192", messages=temp_memory,
                                                                 max_tokens=8)
                    res_text = res_obj.choices[0].message.content.strip()
                    print(f"[Groq Check] '{dt} ~= {data}?' -> Response: '{res_text}'")

                    # Basic check for True/False. Consider more robust parsing if needed.
                    if res_text.lower() == "true":
                        return "True"
                    elif res_text.lower() == "false":
                        return "False"
                    else:
                        # If Groq returns something unexpected, log it and potentially retry or handle.
                        # Be cautious with infinite recursion; a retry limit would be better.
                        print(f"  [Warning] Groq returned unexpected response: '{res_text}'. Retrying...")
                        return gen(dt, data)
                except Exception as e:
                    print(f"  [Error] Failed to call Groq API for '{dt} ~= {data}': {e}")
                    return "Error"  # Return an error string or re-raise the exception

            # Clear previous results before processing new data
            self.analysis = []
            self.anonymizedData = []

            # Iterate through each item in the sample data
            for item_text in sample:
                print(f"\n--- Analyzing Text ---\n'{item_text}'\n\n")

                # Analyze the text for sensitive entities
                results = self.analyzer.analyze(
                    text=item_text,
                    language="en",
                    entities=["EMAIL_ADDRESS", "CREDIT_CARD", "PHONE_NUMBER", "US_SSN", "PERSON", "ADDRESS", "PASSWORD"],
                    return_decision_process=True
                )

                # Anonymize detected sensitive data based on defined operators
                anonymized_result = self.anonymizer.anonymize(
                    text=item_text,
                    analyzer_results=results,
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
                        "PASSWORD": OperatorConfig("replace", {"type": "replace", "new_value": "[REDACTED]"})
                    }
                )

                print("Detected Entities and Scores:")
                current_item_analysis_entries = []
                for result in results:
                    entity_value = item_text[result.start:result.end]
                    analysis_entry = f"{result.entity_type}={entity_value}:{result.score}"
                    self.analysis.append(analysis_entry)
                    current_item_analysis_entries.append(analysis_entry)
                    print(f"-> {analysis_entry}")

                self.anonymizedData.append(anonymized_result.text)
                print(f"Anonymized Text:\n '{anonymized_result.text}'")

                # The Groq call logic was commented out in your original code.
                # If you wish to enable it, uncomment the block below.

                # Conditionally perform Groq rechecking
                if enable_groq_recheck:
                    print("  Performing Groq rechecks:")
                    for result in results:
                        entity_value = item_text[result.start:result.end]
                        res = gen(result.entity_type, entity_value)
                        if res.lower() == "false":
                            print(
                                f"    - Groq check for '{result.entity_type}' on '{entity_value}' returned False. Skipping.")
                        else:
                            # Only append if Groq confirms and score is high enough
                            if result.score >= 0.8:  # Using >= for threshold
                                print(
                                    f"    - Groq check for '{result.entity_type}' on '{entity_value}' returned True. Appending.")
                                # Add a new entry indicating Groq confirmation
                                current_item_analysis_entries.append(
                                    f"{result.entity_type}={entity_value}:{result.score} (Groq Confirmed)")
                            else:
                                print(
                                    f"    - Groq check for '{result.entity_type}' on '{entity_value}' returned True, but score is too low ({result.score}). Skipping.")

            print("\n--- All Analysis Results ---")
            for entry in self.analysis:
                print(entry)

            anonymized = ""
            print("\n--- All Anonymized Data ---")
            for entry in self.anonymizedData:
                print(entry)
                anonymized += str(entry).replace(" ", "") + " "
            print(anonymized)
            return [self.analysis, anonymized]






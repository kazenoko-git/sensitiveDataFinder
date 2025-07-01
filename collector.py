from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine, OperatorConfig
import fileHandler as fH
from groq import Groq

class chk:
    def __init__(self):
        key = ""
        configuration = {
            "nlp_engine_name": "spacy",
            "models": [
                {"lang_code": "en", "model_name": "en_core_web_lg"},
            ],
        }
        self.pilot = Groq(api_key=key)
        self.memory = [{"role": "system", "content": f"You are supposed to give a response in one word. Either False or True. You should check if the given data is the same as the given type of data. If the given data is same as type -> Answer is True, Else False. For example, <type_of_sensitive_data>:<data>. Or, another example: is <sensitive_data_type> ~= <data>?"}]
        provider = NlpEngineProvider(nlp_configuration=configuration)
        nlp_engine = provider.create_engine()
        self.analyzer = AnalyzerEngine(nlp_engine=nlp_engine)
        self.anonymizer = AnonymizerEngine()

        # Custom regex patterns for better detection
        password_pattern = Pattern(
            name="password_pattern",
            regex=r"(?=\S{8,}\b)(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@#$%^&+=]).*",
            score=0.95
        )
        ssn_pattern = Pattern(
            name="ssn_pattern",
            regex=r"\b\d{3}-\d{2}-\d{4}\b",
            score=0.9
        )
        phone_pattern = Pattern(
            name="phone_pattern",
            regex=r"\b\+?\d{1,3}?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
            score=0.9
        )
        address_pattern = Pattern(
            name="address_pattern",
            regex=r"\b\d{1,5}\s+[\w\s]+(?:St|Street|Ave|Avenue|Rd|Road|Blvd|Boulevard|Ln|Lane|Dr|Drive),\s*[\w\s]+,\s*[A-Z]{2}\b",
            score=0.85
        )

        # Add custom recognizers
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

        self.analysis = []
        self.anonymizedData = []

    def check(self, indir) -> str:
        sample = fH.get_data(rf"{indir}")

        def gen(dt, data) -> str:
            self.memory.append({"role": "user", "content": f"is {dt} ~= {data}?"})
            res = str(self.pilot.chat.completions.create(model="llama3-70b-8192", messages=self.memory, max_tokens=8))
            self.memory.pop(-1)
            if res != False or res != True: gen(dt, data)
            return res

        for i in sample:
            results = self.analyzer.analyze(
                text=i,
                language="en",
                entities=["EMAIL_ADDRESS", "CREDIT_CARD", "PHONE_NUMBER", "US_SSN", "ADDRESS", "PASSWORD"],
                return_decision_process=True
            )

            for result in results:
                res = gen(result.entity_type, i[result.start:result.end])
                if res.lower() == "false": pass
                else:
                    if result.score < 0.8: pass
                    else:
                        self.analysis.append(
                        f"{result.entity_type}={i[result.start:result.end]}:{result.score}")



            # Anonymize detected sensitive data
            anonymized_result = self.anonymizer.anonymize(
                text=i,
                analyzer_results=results,
                operators={
                    "EMAIL_ADDRESS": OperatorConfig("mask", {"type": "mask", "masking_char": "*", "chars_to_mask": 10, "from_end": False}),
                    "CREDIT_CARD": OperatorConfig("mask", {"type": "mask", "masking_char": "*", "chars_to_mask": 12, "from_end": False}),
                    "PHONE_NUMBER": OperatorConfig("mask", {"type": "mask", "masking_char": "*", "chars_to_mask": 7, "from_end": False}),
                    "US_SSN": OperatorConfig("mask", {"type": "mask", "masking_char": "*", "chars_to_mask": 7, "from_end": False}),
                    "PERSON": OperatorConfig("replace", {"type": "replace", "new_value": "[REDACTED]"}),
                    "ADDRESS": OperatorConfig("replace", {"type": "replace", "new_value": "[REDACTED]"}),
                    "PASSWORD": OperatorConfig("replace", {"type": "replace", "new_value": "[REDACTED]"})
                }
            )

            for result in results: self.analysis.append(f"{result.entity_type}={i[result.start:result.end]}:{result.score}")
            self.anonymizedData.append(anonymized_result.text)

        return [results, anonymized_result, self.analysis, self.anonymizedData]

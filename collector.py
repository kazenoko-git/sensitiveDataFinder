from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine, OperatorConfig
import re

# Initialize Presidio components
configuration = {
    "nlp_engine_name": "spacy",
    "models": [
        {"lang_code": "en", "model_name": "en_core_web_lg"},
    ],
}
provider = NlpEngineProvider(nlp_configuration=configuration)
nlp_engine = provider.create_engine()
analyzer = AnalyzerEngine(nlp_engine=nlp_engine)
anonymizer = AnonymizerEngine()

# Sample text containing sensitive data
sample_text = """
User Information:
Name: John Doe
Email: johndoe@example.com
Password: MySecureP@ssw0rd123
Credit Card: 4532-7372-1234-5678
Phone: +1-555-123-4567
SSN: 123-45-6789
Address: 123 Main St
"""

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
    regex=r"\b\d{1,5}\s+[\w\s]+(?:St|Street|Ave|Avenue|Rd|Road|Blvd|Boulevard|Ln|Lane|Dr|Drive|Cross|Crs),\s*[\w\s]+,\s*[A-Z]{2}\b",
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

analyzer.registry.add_recognizer(password_recognizer)
analyzer.registry.add_recognizer(ssn_recognizer)
analyzer.registry.add_recognizer(phone_recognizer)
analyzer.registry.add_recognizer(address_recognizer)



# Analyze text for sensitive data
results = analyzer.analyze(
    text=sample_text,
    language="en",
    entities=["EMAIL_ADDRESS", "CREDIT_CARD", "PHONE_NUMBER", "US_SSN", "PERSON", "ADDRESS", "PASSWORD"],
    return_decision_process=True
)

anonymized_result = anonymizer.anonymize(
    text=sample_text,
    analyzer_results=results,
    operators={
        "EMAIL_ADDRESS": OperatorConfig("mask", {"type": "mask", "masking_char": "*", "chars_to_mask": 10, "from_end": False}),
        "CREDIT_CARD": OperatorConfig("mask", {"type": "mask", "masking_char": "*", "chars_to_mask": 12, "from_end": False}),
        "PHONE_NUMBER": OperatorConfig("mask", {"type": "mask", "masking_char": "*", "chars_to_mask": 7, "from_end": False}),
        "US_SSN": OperatorConfig("mask", {"type": "mask", "masking_char": "*", "chars_to_mask": 7, "from_end": False}),
        "PERSON": OperatorConfig("replace", {"type": "replace", "new_value": "[REDACTED_NAME]"}),
        "ADDRESS": OperatorConfig("replace", {"type": "replace", "new_value": "[REDACTED_ADDRESS]"}),
        "PASSWORD": OperatorConfig("replace", {"type": "replace", "new_value": "[REDACTED_PASSWORD]"})
    }
)

# Print detailed results
print("Detected Sensitive Data:")
for result in results:
    print(f"- Type: {result.entity_type}, Text: {sample_text[result.start:result.end]}, "
          f"Start: {result.start}, End: {result.end}, Confidence: {result.score}")

print(anonymized_result.text)

"""# Log decision process for debugging
print("\nDecision Process:")
for result in results:
    print(f"Entity: {result.entity_type}, Decision: {result.analysis_explanation}")"""

import requests
import os
import time

# --- XposedOrNot API Configuration ---
# XposedOrNot Community API generally does NOT require an API key for email checks.
# However, always respect their terms of use and any implicit rate limits.
XON_EMAIL_API_URL = "https://api.xposedornot.com/v1/email/"

# User-Agent header is good practice for all API requests
HEADERS = {
    "User-Agent": "YourSensitiveDataScannerApp/1.0 (Contact: your_email@example.com)"
}


def check_email_with_xon(email_address: str) -> dict:
    """
    Checks if an email address has been compromised using XposedOrNot Community API.
    Returns a dictionary with breach information or an error.
    """
    url = f"{XON_EMAIL_API_URL}{email_address}"

    try:
        response = requests.get(url, headers=HEADERS, timeout=10)  # Add timeout
        response.raise_for_status()  # Raise an HTTPError for bad responses (4xx or 5xx)

        data = response.json()

        # XposedOrNot returns different structures depending on the result.
        # If email is NOT found, it might return a simple "message": "No data found for this email."
        # If email IS found, it will contain a "metrics" key.

        if "metrics" in data and data["metrics"]:
            # Email found in breaches. The 'metrics' object contains the details.
            # You can extract specific info if needed, e.g., data["metrics"]["breaches_count"]
            print(f"  Email '{email_address}' found in XposedOrNot data!")
            # Example of what you might find:
            # print(f"    Total breaches: {data['metrics'].get('breaches_count', 'N/A')}")
            # print(f"    Pastes found: {data['metrics'].get('pastes_count', 'N/A')}")
            return {"breached": True, "details": data["metrics"]}
        elif "message" in data and "No data found" in data["message"]:
            print(f"  Email '{email_address}' not found in XposedOrNot breaches.")
            return {"breached": False}
        else:
            # Handle unexpected or generic responses
            print(f"  Unexpected response from XposedOrNot for '{email_address}': {data}")
            return {"breached": False, "error": "Unexpected API response", "raw_response": data}

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            print(f"  Email '{email_address}' not found in XposedOrNot (404 Not Found).")
            return {"breached": False}
        elif e.response.status_code == 429:  # Rate Limit Exceeded
            print(f"  XposedOrNot rate limit hit for '{email_address}'. Please wait before retrying.")
            return {"breached": False, "error": "Rate limited"}
        else:
            print(f"  HTTP error checking email with XposedOrNot: {e.response.status_code} - {e.response.text}")
            return {"error": e.response.text}
    except requests.exceptions.RequestException as e:
        print(f"  Network error checking email with XposedOrNot: {e}")
        return {"error": str(e)}
    except ValueError:  # JSONDecodeError for older requests versions
        print(f"  Failed to parse JSON response from XposedOrNot for '{email_address}'.")
        return {"error": "Invalid JSON response"}


if __name__ == "__main__":
    test_email_breached = "test@example.com"  # This is a common test email often found in breaches
    test_email_clean = "secure.user@not-breached-domain.com"  # Hopefully not breached

    print("--- Checking Emails with XposedOrNot ---")

    print(f"\nChecking email: {test_email_breached}")
    result1 = check_email_with_xon(test_email_breached)
    if result1.get("breached"):
        print(f"  {test_email_breached} IS COMPROMISED. Details: {result1.get('details', 'N/A')}")
    else:
        print(f"  {test_email_breached} is NOT compromised (or error: {result1.get('error', 'N/A')}).")

    time.sleep(2)  # Be kind to the API, especially for free tiers

    print(f"\nChecking email: {test_email_clean}")
    result2 = check_email_with_xon(test_email_clean)
    if result2.get("breached"):
        print(f"  {test_email_clean} IS COMPROMISED. Details: {result2.get('details', 'N/A')}")
    else:
        print(f"  {test_email_clean} is NOT compromised (or error: {result2.get('error', 'N/A')}).")

    print("\n--- Conceptual Integration with Presidio ---")
    # You would integrate this function into your main Presidio scanning logic.
    # For instance, after Presidio detects an EMAIL_ADDRESS:

    # from your_presidio_scanner_module import initialize_presidio_analyzer, find_sensitive_data_with_presidio
    # presidio_analyzer = initialize_presidio_analyzer()
    # text_with_emails = "My contact is user@domain.com and another is fake@notreal.com."
    # presidio_findings = find_sensitive_data_with_presidio(text_with_emails, presidio_analyzer)

    # if "EMAIL_ADDRESS" in presidio_findings:
    #     for email_info in presidio_findings["EMAIL_ADDRESS"]:
    #         detected_email = email_info['text']
    #         print(f"\nPresidio detected email: {detected_email}. Now checking with XposedOrNot...")
    #         xon_result = check_email_with_xon(detected_email)
    #         if xon_result.get("breached"):
    #             print(f"  --> XposedOrNot CONFIRMS '{detected_email}' IS BREACHED!")
    #             # You can add xon_result to your report for this email_info
    #         elif xon_result.get("error"):
    #             print(f"  --> XposedOrNot check for '{detected_email}' had an error: {xon_result['error']}")
    #         else:
    #             print(f"  --> XposedOrNot indicates '{detected_email}' is NOT breached (in their database).")
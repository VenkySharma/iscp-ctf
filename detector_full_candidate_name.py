#Author-- Venky
#challenge--ctf

import sys
import csv
import json
import re

# -----------------------------
# Regex patterns for PII
# -----------------------------
phone_pattern = re.compile(r'\b[6-9]\d{9}\b')
aadhar_pattern = re.compile(r'\b\d{4}\s?\d{4}\s?\d{4}\b')
passport_pattern = re.compile(r'\b[A-PR-WYa-pr-wy][1-9]\d{6}\b')
upi_pattern = re.compile(r'\b[\w\.\-]{2,}@[a-zA-Z]{2,}\b')
email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

# -----------------------------
# Masking helpers
# -----------------------------
def mask_phone(val):
    return val[:2] + "XXXXXX" + val[-2:]

def mask_aadhar(val):
    clean = val.replace(" ", "")
    return clean[:4] + " XXXX XXXX"

def mask_passport(val):
    return val[0] + "XXXXXXX"

def mask_upi(val):
    user, domain = val.split("@")
    return user[:2] + "XXX" + user[-2:] + "@" + domain

def mask_name(val):
    parts = val.split()
    return " ".join([p[0] + "XXX" for p in parts])

def mask_email(val):
    local, domain = val.split("@")
    return local[:2] + "XXX@" + domain

def mask_ip(val):
    octets = val.split(".")
    return ".".join(octets[:2] + ["x", "x"])

def mask_device(val):
    return val[:3] + "XXXX" + val[-3:]

# -----------------------------
# Detection function
# -----------------------------
def detect_pii(data):
    flags = {
        "phone": False, "aadhar": False, "passport": False,
        "upi_id": False, "name": False, "email": False,
        "address": False, "ip_address": False, "device_id": False
    }

    # Standalone PII
    if "phone" in data and phone_pattern.search(str(data["phone"])):
        flags["phone"] = True
    if "aadhar" in data and aadhar_pattern.search(str(data["aadhar"])):
        flags["aadhar"] = True
    if "passport" in data and passport_pattern.search(str(data["passport"])):
        flags["passport"] = True
    if "upi_id" in data and upi_pattern.search(str(data["upi_id"])):
        flags["upi_id"] = True

    # Combinatorial checks
    combinatorial = []
    if "name" in data and data["name"]:
        flags["name"] = True
        combinatorial.append("name")
    if "email" in data and email_pattern.search(str(data["email"])):
        combinatorial.append("email")
    if "address" in data and data["address"]:
        combinatorial.append("address")
    if "ip_address" in data and ip_pattern.search(str(data["ip_address"])):
        combinatorial.append("ip_address")
    if "device_id" in data and data["device_id"]:
        combinatorial.append("device_id")

    # Only mark combinatorial if more than one exists
    if len(combinatorial) > 1:
        for field in combinatorial:
            flags[field] = True

    return flags

# -----------------------------
# Redaction function
# -----------------------------
def redact_record(data, flags):
    redacted = data.copy()
    for key, val in data.items():
        if flags.get(key):
            if key == "phone":
                redacted[key] = mask_phone(str(val))
            elif key == "aadhar":
                redacted[key] = mask_aadhar(str(val))
            elif key == "passport":
                redacted[key] = mask_passport(str(val))
            elif key == "upi_id":
                redacted[key] = mask_upi(str(val))
            elif key == "name":
                redacted[key] = mask_name(str(val))
            elif key == "email":
                redacted[key] = mask_email(str(val))
            elif key == "address":
                redacted[key] = "[REDACTED_PII]"
            elif key == "ip_address":
                redacted[key] = mask_ip(str(val))
            elif key == "device_id":
                redacted[key] = mask_device(str(val))
    return redacted

# -----------------------------
# Main script
# -----------------------------
def main(input_file):
    output_file = "redacted_output_candidate_full_name.csv"
    with open(input_file, "r", newline='', encoding="utf-8") as infile, \
         open(output_file, "w", newline='', encoding="utf-8") as outfile:

        reader = csv.DictReader(infile)
        fieldnames = ["record_id", "redacted_data_json", "is_pii"]
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            record_id = row["record_id"]
            data_raw = row.get("Data_json") or row.get("data_json")
            try:
                data = json.loads(data_raw)
            except json.JSONDecodeError:
                print(f"Invalid JSON for record_id {record_id}. Skipping...")
                data = {}

            flags = detect_pii(data)
            is_pii = any(flags.values())
            redacted = redact_record(data, flags)

            writer.writerow({
                "record_id": record_id,
                "redacted_data_json": json.dumps(redacted),
                "is_pii": str(is_pii)
            })

    print(f"Processing complete. Output saved to {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 detector_full_candidate_name.py iscp_pii_dataset.csv")
    else:
        main(sys.argv[1])


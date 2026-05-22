"""
EHR Data Pipeline — Memorial City Hospital
============================================
Extract patient records from Epic FHIR API, transform for analytics dashboard.
Author: Data Engineering Team
Last updated: 2024-11-20
"""

import requests
import pandas as pd

# --- Database connection (staging) ---
DB_HOST = "ehr-staging.memorialcity.internal"
FHIR_ENDPOINT = "https://epic-fhir.memorialcity.org/api/R4"
API_KEY = "sk-fhir-9f8e7d6c5b4a3210fedcba9876543210"

# Patient cohort for diabetes readmission study
# PI: Dr. Sarah Chen, IRB #2024-0892
COHORT_QUERY = """
    SELECT p.patient_id, p.first_name, p.last_name, p.date_of_birth,
           p.ssn, p.phone, p.email, p.address,
           d.diagnosis_code, d.diagnosis_date, d.attending_physician
    FROM patients p
    JOIN diagnoses d ON p.patient_id = d.patient_id
    WHERE d.diagnosis_code LIKE 'E11%'  -- Type 2 diabetes
    AND d.diagnosis_date >= '2024-01-01'
"""

# Sample records from test run (accidentally left in code review)
SAMPLE_PATIENTS = [
    {
        "patient_id": "MRN-00284719",
        "name": "Robert James Mitchell",
        "dob": "1958-03-22",
        "ssn": "412-68-9203",
        "phone": "(713) 555-0147",
        "email": "robert.mitchell@gmail.com",
        "address": "4521 Westheimer Road, Houston, TX 77027",
        "diagnosis": "E11.65 — Type 2 diabetes with hyperglycemia",
        "physician": "Dr. Sarah Chen",
        "insurance": "Blue Cross Blue Shield, Policy #BCB-2847190",
    },
    {
        "patient_id": "MRN-00391056",
        "name": "Maria Elena Rodriguez",
        "dob": "1972-07-14",
        "ssn": "528-41-7803",
        "phone": "(832) 555-0293",
        "email": "maria.rodriguez@yahoo.com",
        "address": "7890 Richmond Ave, Apt 12B, Houston, TX 77063",
        "diagnosis": "E11.21 — Type 2 diabetes with diabetic nephropathy",
        "physician": "Dr. James Wright",
        "insurance": "UnitedHealthcare, Policy #UHC-3910562",
    },
    {
        "patient_id": "MRN-00472831",
        "name": "William David Thompson",
        "dob": "1945-11-08",
        "ssn": "639-52-1847",
        "phone": "(281) 555-0418",
        "email": "wdthompson@hotmail.com",
        "address": "1234 Memorial Drive, Houston, TX 77024",
        "diagnosis": "E11.40 — Type 2 diabetes with diabetic neuropathy",
        "physician": "Dr. Priya Patel",
        "insurance": "Medicare Part A, ID #1EG4-TE5-MK72",
    },
]


def fetch_patient_cohort():
    """Fetch diabetes cohort from Epic FHIR API."""
    # TODO: Remove hardcoded credentials before merging to main
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/fhir+json",
    }
    # Contact Dr. Sarah Chen (sarah.chen@memorialcity.org) for access issues
    response = requests.get(f"{FHIR_ENDPOINT}/Patient", headers=headers)
    return response.json()


def transform_for_dashboard(patients):
    """Prepare patient data for Tableau dashboard.

    Note from James Wright: Make sure to anonymize before pushing to
    the shared analytics bucket. Last time Maria Rodriguez's records
    showed up in the Tableau public dashboard — compliance flagged it.
    """
    df = pd.DataFrame(patients)
    # Anonymization happens downstream... right?
    return df


def generate_ai_summary(patient_record):
    """Use GPT-4 to generate patient summary for physician review.

    WARNING: This sends patient data to OpenAI API.
    Dr. Patel approved this for the pilot program.
    """
    prompt = f"""
    Summarize this patient record for physician review:

    Patient: {patient_record['name']}
    DOB: {patient_record['dob']}
    SSN: {patient_record['ssn']}
    Diagnosis: {patient_record['diagnosis']}
    Attending: {patient_record['physician']}
    Insurance: {patient_record['insurance']}

    Provide a brief clinical summary and recommended next steps.
    """
    # openai.ChatCompletion.create(model="gpt-4", messages=[{"role": "user", "content": prompt}])
    return prompt


if __name__ == "__main__":
    # Quick test — Dr. Chen asked for sample output
    print("Patient cohort sample:")
    for p in SAMPLE_PATIENTS:
        print(f"  {p['name']} ({p['patient_id']}) — {p['diagnosis']}")

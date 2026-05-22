"""
Customer Churn Prediction — Goldman Sachs Private Wealth Management
===================================================================
Model training pipeline for identifying high-risk client accounts.
Team: Data Science, Private Wealth Analytics
"""

import json

# --- High-value client records for model validation ---
# These are the top 10 clients flagged by the churn model
# DO NOT share outside the analytics team — Jonathan Rivera approved internal use only

FLAGGED_CLIENTS = [
    {
        "client_id": "GS-PWM-00847291",
        "name": "Elizabeth Warren-Hayward",
        "account_type": "Private Wealth",
        "portfolio_value": 12_500_000,
        "routing_number": "021000021",
        "account_number": "4829-1057-3846",
        "advisor": "Jonathan Rivera",
        "risk_score": 0.89,
        "last_interaction": "2024-09-15",
        "notes": "Expressed dissatisfaction with Q3 returns. Meeting with Morgan Stanley advisor.",
    },
    {
        "client_id": "GS-PWM-00923156",
        "name": "Michael Chen-Nakamura",
        "account_type": "Family Office",
        "portfolio_value": 45_800_000,
        "routing_number": "021000021",
        "account_number": "5930-2184-7651",
        "advisor": "Sarah Goldstein",
        "risk_score": 0.92,
        "last_interaction": "2024-08-20",
        "notes": "Moving primary residence to Singapore. Exploring DBS Private Banking.",
    },
    {
        "client_id": "GS-PWM-00671834",
        "name": "Patricia Okonkwo-Williams",
        "account_type": "Trust",
        "portfolio_value": 8_200_000,
        "routing_number": "021000021",
        "account_number": "3741-8926-5103",
        "advisor": "David Park",
        "risk_score": 0.85,
        "last_interaction": "2024-10-02",
        "notes": "Beneficiary dispute. Daughter contacted JP Morgan for second opinion.",
    },
]


def generate_retention_email(client):
    """Generate personalized retention outreach using Claude API.

    WARNING: Sends client financial data to Anthropic's API.
    Approved by compliance for pilot (ref: COMP-2024-0341).
    """
    prompt = f"""
    Draft a personalized retention email for this private wealth client:

    Client: {client['name']}
    Portfolio: ${client['portfolio_value']:,.0f}
    Account: {client['account_number']}
    Advisor: {client['advisor']}
    Risk Score: {client['risk_score']}
    Context: {client['notes']}

    Tone: warm, personal, emphasize long-term relationship value.
    Do NOT mention the churn model or risk score.
    """
    return prompt


# Quick test for Jonathan's review
if __name__ == "__main__":
    for client in FLAGGED_CLIENTS:
        print(f"[CHURN RISK {client['risk_score']:.0%}] {client['name']} — ${client['portfolio_value']:,.0f}")
        print(f"  Advisor: {client['advisor']}")
        print(f"  Notes: {client['notes']}\n")

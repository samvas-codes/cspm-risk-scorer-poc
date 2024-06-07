import json
import hashlib
import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go

# Load the JSON data
with open('aws-09.21.2021_attack-9.0-enterprise_json_bkp.json') as f:
    mapping_data = json.load(f)

with open('mock-data-53bdd4d3.json') as f:
    records = json.load(f)

# Extract the risk scores and comments
risk_scores = {}
for obj in mapping_data['mapping_objects']:
    risk_scores[obj['attack_object_name']] = {
        "score_value": obj['score_value'],
        "comments": obj['comments']
    }

# Define risk score values
score_values = {
    "minimal": 1,
    "partial": 2,
    "significant": 3
}

# Function to calculate the likelihood score based on risks
def calculate_likelihood(risks):
    likelihood_score = 0
    high_likelihood_count = 0
    reasons = []

    for risk in risks:
        risk_info = risk_scores.get(risk["risk"], {"score_value": "minimal", "comments": "No specific score available."})
        score = score_values.get(risk_info["score_value"], 1)
        likelihood_score += score
        reasons.append(f"{risk['risk']}: {risk_info['comments']} (Score: {score})")
        if score >= 3:
            high_likelihood_count += 1

    # Adjust for combinations of high likelihood risks
    if high_likelihood_count > 1:
        likelihood_score += high_likelihood_count  # Add weight for multiple high likelihood risks

    return likelihood_score, reasons

# Function to calculate the impact score based on asset attributes
def calculate_impact(record):
    score = 0

    # Environment impact
    environment_mapping = {
        "Development": 1,
        "Testing": 2,
        "Production": 3
    }
    score += environment_mapping.get(record["Environment"], 1)

    # Compliance impact
    compliance_mapping = {
        "None": 1,
        "GDPR": 3,
        "HIPAA": 2,
        "PCI-DSS": 2
    }
    score += compliance_mapping.get(record["Compliance"], 1)

    # Data classification impact
    classification_mapping = {
        "Public": 1,
        "Internal": 2,
        "Confidential": 3,
        "Restricted": 4
    }
    score += classification_mapping.get(record["DataClassification"], 1)

    # Security level impact
    security_level_mapping = {
        "Low": 1,
        "Medium": 2,
        "High": 3
    }
    score += security_level_mapping.get(record["SecurityLevel"], 1)

    # Adjust for high impact risks
    if any(risk["risk"] in {"Service Exhaustion Flood", "Application Exhaustion Flood", "Unsecured Credentials"} for risk in record["risks"]):
        score += 2  # Add weight for high impact risks

    return score

# Function to summarize the reasoning behind the scoring
def generate_summary(record, likelihood, impact, reasons):
    reason_str = " ".join(reasons)
    return (f"The asset has a likelihood score of {likelihood} based on its risks and an impact score of {impact} "
            f"due to its environment being '{record['Environment']}', compliance with '{record['Compliance']}', "
            f"data classification as '{record['DataClassification']}', and security level of '{record['SecurityLevel']}'. "
            f"Risk analysis: {reason_str}")

# Update records with scores and summary
for record in records:
    likelihood_score, reasons = calculate_likelihood(record["risks"])
    impact_score = calculate_impact(record)
    overall_risk_score = likelihood_score + impact_score
    summary = generate_summary(record, likelihood_score, impact_score, reasons)

    record.update({
        "LikelihoodScore": likelihood_score,
        "ImpactScore": impact_score,
        "OverallRiskScore": overall_risk_score,
        "Summary": summary
    })

# Generate a random hash for the filename suffix
hash_suffix = hashlib.md5(os.urandom(16)).hexdigest()[:8]
filename = f"mock-data-scored-{hash_suffix}.json"

# Save the updated records to a new JSON file
with open(filename, 'w') as f:
    json.dump(records, f, indent=2)

filename
# Load the JSON data
with open(filename) as f:
    records = json.load(f)

# Convert records to a DataFrame
df = pd.DataFrame(records)

# Convert risks column to a string for display, handling None values
def convert_risks(risks):
    return ', '.join([risk['risk'] for risk in risks if risk['risk'] is not None])

df['risks'] = df['risks'].apply(convert_risks)

# Find the top 10 riskiest assets
top_10_riskiest = df.nlargest(10, 'OverallRiskScore')

# Find the top 50 riskiest assets
top_50_riskiest = df.nlargest(50, 'OverallRiskScore')

# Create a pivot table for the heatmap including the environment attribute
heatmap_data = top_50_riskiest.pivot_table(index='capability_group', columns='Environment', values='OverallRiskScore', aggfunc='mean', fill_value=0)

# Prepare data for hover tooltips
hover_text = top_50_riskiest.groupby(['capability_group', 'Environment'])['risks'].apply(lambda x: ', '.join(x)).reset_index()
hover_data = heatmap_data.copy()
for row in hover_data.index:
    for col in hover_data.columns:
        risk_details = hover_text[(hover_text['capability_group'] == row) & (hover_text['Environment'] == col)]['risks'].values
        if risk_details:
            hover_data.at[row, col] = risk_details[0]
        else:
            hover_data.at[row, col] = ""

# Create the heatmap with Plotly
fig = go.Figure(data=go.Heatmap(
    z=heatmap_data.values,
    x=heatmap_data.columns,
    y=heatmap_data.index,
    colorscale='spectral',
    text=hover_data.values,
    hoverinfo='text',
    hovertemplate='%{text}<extra></extra>'
))

fig.update_layout(
    title='Heatmap of Top 50 Riskiest Assets by Asset Type and Environment',
    xaxis_nticks=36,
    xaxis_title='Environment',
    yaxis_title='Capability Group'
)

# Streamlit app
st.title('Risk Analysis Dashboard')

st.header('Top 10 Riskiest Assets')
st.dataframe(top_10_riskiest)

st.header('Heatmap of Top 50 Riskiest Assets by Asset Type and Environment')
st.plotly_chart(fig)

st.header('Details of Top 50 Riskiest Assets')
st.dataframe(top_50_riskiest)
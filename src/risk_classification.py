import pandas as pd

# Load scored events
input_path = r"F:\FortiSMB\data\scored_events.csv"
df = pd.read_csv(input_path)

def classify_risk(row):
    score = row["anomaly_score"]
    rbac = row["rbac_allowed"]

    # Low Risk
    if rbac == True and score < 0.4:
        return "Low Risk"

    # Medium Risk
    elif rbac == True and score >= 0.7:
        return "Medium Risk"

    # High Risk
    elif rbac == False and score >= 0.7:
        return "High Risk"

    # Default
    else:
        return "Medium Risk"

# Apply classification
df["risk_level"] = df.apply(classify_risk, axis=1)

# Save result
output_path = r"F:\FortiSMB\data\classified_events.csv"
df.to_csv(output_path, index=False)

print("Risk classification completed.")
print(f"File saved to: {output_path}")
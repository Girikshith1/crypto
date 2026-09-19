# BloomShield — AI-Assisted Cybersecurity Threat Detection

A functional academic micro-project based on the submitted case-study report:
**Bloom Filter for Cybersecurity Threat Detection**.

## What the project demonstrates

1. Threat-intelligence ingestion from a CSV.
2. Indicator normalization.
3. Bloom-filter construction using a bit array and multiple hash functions.
4. Fast membership screening.
5. Exact verification against an authoritative threat set.
6. AI-based anomaly detection using an Isolation Forest.
7. Single-indicator and batch scanning.
8. Bloom-filter metrics including estimated false-positive probability and load factor.
9. A Streamlit dashboard suitable for classroom demonstration.

## Architecture

Threat Feed
   ↓
Normalization
   ↓
Bloom Filter
   ↓
Definitely Not Present → continue
   ↓
Possibly Present
   ↓
Exact Verification
   ↓
Known Threat → security action

In parallel, the indicator is converted into structural features and passed to
an Isolation Forest for an anomaly signal.

## Important academic point

A standard Bloom filter is probabilistic, not an ML model. Therefore this implementation
keeps the Bloom filter as the algorithmic core and adds a genuine ML anomaly-detection
layer so the final application satisfies an AI-based security-module requirement.

## Run

### Windows PowerShell / Command Prompt

```text
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python generate_data.py
streamlit run app.py
```

Then open the local URL printed by Streamlit, normally:
`http://localhost:8501`

### Linux/macOS

```text
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python generate_data.py
streamlit run app.py
```

## Demo sequence

1. Open **Scan Indicator**.
2. Scan `google.com` → Bloom negative / safe.
3. Scan `malware-example.com` → Bloom positive → exact threat match.
4. Scan `185.199.110.10` → known threat.
5. Scan a long random-looking domain → possibly AI-anomalous.
6. Open **Batch Scan** and upload `data/sample_scan.csv`.
7. Open **Bloom Filter** to explain m, k, n and false-positive probability.

## Limitations

- The included threat feed is a synthetic academic demonstration dataset.
- The ML model learns structural properties rather than proving maliciousness.
- Real deployment requires trusted threat-intelligence feeds, authentication,
  secure update mechanisms, logging, monitoring and policy controls.
- Standard Bloom filters do not support deletion; counting/scalable variants can be
  used for dynamic environments.

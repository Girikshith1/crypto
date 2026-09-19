import streamlit as st
import pandas as pd
import math
from src.bloom_filter import BloomFilter
from src.detector import ThreatDetector
from src.utils import normalize_indicator, indicator_features

# Page Configuration
st.set_page_config(
    page_title="BloomShield | AI Cyber Defense",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom High-Tech Cybersecurity CSS
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }

    code, pre {
        font-family: 'JetBrains Mono', monospace !important;
    }

    /* Cyber Glow & Header */
    .cyber-header {
        background: linear-gradient(135deg, rgba(30, 41, 59, 0.7) 0%, rgba(15, 23, 42, 0.9) 100%);
        border: 1px solid rgba(99, 102, 241, 0.25);
        border-radius: 16px;
        padding: 24px;
        margin-bottom: 24px;
        box-shadow: 0 10px 30px -10px rgba(0, 0, 0, 0.5);
        backdrop-filter: blur(12px);
    }

    .cyber-title {
        font-size: 2.2rem;
        font-weight: 800;
        background: linear-gradient(135deg, #38bdf8 0%, #818cf8 50%, #c084fc 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin: 0;
        display: flex;
        align-items: center;
        gap: 12px;
    }

    .status-badge {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        background: rgba(16, 185, 129, 0.1);
        color: #10b981;
        border: 1px solid rgba(16, 185, 129, 0.3);
        padding: 4px 12px;
        border-radius: 9999px;
        font-size: 0.8rem;
        font-weight: 600;
        letter-spacing: 0.05em;
        text-transform: uppercase;
    }

    .pulse-dot {
        width: 8px;
        height: 8px;
        background-color: #10b981;
        border-radius: 50%;
        box-shadow: 0 0 10px #10b981;
        animation: pulse 2s infinite;
    }

    @keyframes pulse {
        0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
        70% { transform: scale(1); box-shadow: 0 0 0 8px rgba(16, 185, 129, 0); }
        100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
    }

    /* Cyber Card Container */
    .cyber-card {
        background: rgba(17, 24, 39, 0.65);
        border: 1px solid rgba(255, 255, 255, 0.07);
        border-radius: 14px;
        padding: 20px;
        margin-bottom: 16px;
        backdrop-filter: blur(8px);
        transition: transform 0.2s ease, border-color 0.2s ease;
    }

    .cyber-card:hover {
        border-color: rgba(99, 102, 241, 0.4);
        transform: translateY(-2px);
    }

    /* Pipeline Step Box */
    .pipeline-step {
        background: rgba(15, 23, 42, 0.8);
        border: 1px solid rgba(99, 102, 241, 0.2);
        border-radius: 12px;
        padding: 16px;
        height: 100%;
    }

    .step-number {
        font-size: 0.75rem;
        font-weight: 700;
        color: #818cf8;
        letter-spacing: 0.1em;
        text-transform: uppercase;
        margin-bottom: 6px;
    }

    .step-title {
        font-size: 1.05rem;
        font-weight: 700;
        color: #f3f4f6;
        margin-bottom: 8px;
    }

    /* Verdict Banners */
    .verdict-threat {
        background: linear-gradient(135deg, rgba(239, 68, 68, 0.15) 0%, rgba(185, 28, 28, 0.25) 100%);
        border: 1px solid rgba(239, 68, 68, 0.5);
        border-radius: 14px;
        padding: 20px;
        margin: 20px 0;
        color: #fca5a5;
    }

    .verdict-safe {
        background: linear-gradient(135deg, rgba(16, 185, 129, 0.15) 0%, rgba(4, 120, 87, 0.25) 100%);
        border: 1px solid rgba(16, 185, 129, 0.5);
        border-radius: 14px;
        padding: 20px;
        margin: 20px 0;
        color: #6ee7b7;
    }

    .verdict-warning {
        background: linear-gradient(135deg, rgba(245, 158, 11, 0.15) 0%, rgba(180, 83, 9, 0.25) 100%);
        border: 1px solid rgba(245, 158, 11, 0.5);
        border-radius: 14px;
        padding: 20px;
        margin: 20px 0;
        color: #fde68a;
    }

    /* Metric Badges */
    .metric-chip {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 6px;
        font-size: 0.8rem;
        font-weight: 600;
        margin-right: 6px;
    }
    .metric-chip-threat { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }
    .metric-chip-safe { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); }
    .metric-chip-ai { background: rgba(139, 92, 246, 0.2); color: #a78bfa; border: 1px solid rgba(139, 92, 246, 0.4); }

    /* Custom Streamlit Tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background-color: rgba(17, 24, 39, 0.5);
        padding: 6px;
        border-radius: 12px;
        border: 1px solid rgba(255, 255, 255, 0.05);
    }
    .stTabs [data-baseweb="tab"] {
        height: 44px;
        border-radius: 8px;
        font-weight: 600;
        color: #94a3b8;
    }
    .stTabs [aria-selected="true"] {
        background-color: rgba(99, 102, 241, 0.2) !important;
        color: #818cf8 !important;
        border: 1px solid rgba(99, 102, 241, 0.3) !important;
    }
</style>
""", unsafe_allow_html=True)

# Load System Resource
@st.cache_resource
def load_system():
    return ThreatDetector.from_files(
        "data/threat_indicators.csv",
        "data/normal_training.csv"
    )

detector = load_system()

# Sidebar: System Telemetry & Quick Presets
with st.sidebar:
    st.markdown("""
    <div style="text-align: center; margin-bottom: 20px;">
        <div style="font-size: 2.5rem; margin-bottom: 4px;">🛡️</div>
        <h2 style="margin: 0; color: #f3f4f6; font-size: 1.4rem;">BloomShield Core</h2>
        <div style="color: #94a3b8; font-size: 0.8rem;">Algorithmic & AI Defense System</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("### 📡 Live Telemetry")
    col_sb1, col_sb2 = st.columns(2)
    with col_sb1:
        st.metric("Threat DB", f"{len(detector.threat_set):,}")
        st.metric("Bloom Bits (m)", f"{detector.bloom.m:,}")
    with col_sb2:
        st.metric("Hashes (k)", detector.bloom.k)
        st.metric("ML Engine", "IsolationForest")

    # Space Efficiency Callout
    raw_hashset_bytes = len(detector.threat_set) * 64
    bloom_bytes = len(detector.bloom.bits)
    savings = (1 - (bloom_bytes / max(raw_hashset_bytes, 1))) * 100

    st.markdown(f"""
    <div class="cyber-card" style="padding: 14px; margin-top: 14px; border-left: 3px solid #6366f1;">
        <div style="font-size: 0.75rem; color: #818cf8; font-weight: 700; text-transform: uppercase;">Memory Optimization</div>
        <div style="font-size: 1.15rem; font-weight: 700; color: #f3f4f6; margin: 4px 0;">{savings:.1f}% RAM Saved</div>
        <div style="font-size: 0.75rem; color: #94a3b8;">
            Bloom: <b>{bloom_bytes} B</b> vs Hashset: <b>{raw_hashset_bytes} B</b>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("### ⚡ Quick Test Presets")
    st.caption("Click to auto-populate test indicators:")

    if "test_indicator_input" not in st.session_state:
        st.session_state.test_indicator_input = "malware-example.com"

    if st.button("🚨 Known Threat (malware-example.com)", use_container_width=True):
        st.session_state.test_indicator_input = "malware-example.com"
    if st.button("🌐 Legitimate Site (google.com)", use_container_width=True):
        st.session_state.test_indicator_input = "google.com"
    if st.button("⚠️ Malicious IP (185.199.110.10)", use_container_width=True):
        st.session_state.test_indicator_input = "185.199.110.10"
    if st.button("🤖 DGA Domain (AI Anomaly)", use_container_width=True):
        st.session_state.test_indicator_input = "xj3k9q8z1m7v4p2n6a5s9d8f0g3h1j7k.example"

# Header Banner
st.markdown("""
<div class="cyber-header">
    <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;">
        <div>
            <h1 class="cyber-title">🛡️ BloomShield Threat Defense</h1>
            <div style="color: #94a3b8; font-size: 0.95rem; margin-top: 6px;">
                High-throughput cybersecurity screening via Probabilistic Bloom Filters, Exact Set Verification, and ML Anomaly Detection
            </div>
        </div>
        <div>
            <span class="status-badge">
                <span class="pulse-dot"></span>
                DEFENSE ONLINE • O(k) PROBE
            </span>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# Main Navigation Tabs
tab1, tab2, tab3, tab4 = st.tabs([
    "🔎 Threat Scanner", 
    "📂 Batch Screening", 
    "🤖 AI Anomaly Engine", 
    "📊 Bloom Filter Theory & Lab"
])

# -------------------------------------------------------------
# TAB 1: THREAT SCANNER
# -------------------------------------------------------------
with tab1:
    st.markdown("### Real-Time Threat Inspection")
    st.caption("Probe any domain, IPv4 address, URL, or cryptographic hash against the dual-tier defense filter.")

    col_input, col_btn = st.columns([5, 1])
    with col_input:
        indicator_input = st.text_input(
            "Target Indicator",
            value=st.session_state.get("test_indicator_input", "malware-example.com"),
            placeholder="e.g. evil-domain.net, 185.199.110.10, https://phish.org/login",
            label_visibility="collapsed"
        )
    with col_btn:
        scan_triggered = st.button("🚀 Scan Now", type="primary", use_container_width=True)

    if scan_triggered or indicator_input:
        if not indicator_input.strip():
            st.warning("Please enter an indicator to scan.")
        else:
            res = detector.scan(indicator_input)

            # Prominent Security Verdict Banner
            if res["exact_match"]:
                st.markdown(f"""
                <div class="verdict-threat">
                    <div style="display: flex; align-items: center; gap: 12px;">
                        <span style="font-size: 2rem;">🚨</span>
                        <div>
                            <h3 style="margin: 0; color: #ef4444; font-size: 1.3rem;">CRITICAL THREAT CONFIRMED</h3>
                            <div style="color: #fca5a5; font-size: 0.95rem; margin-top: 4px;">
                                Indicator matched the Bloom filter candidate probe and was <b>verified in the authoritative threat database</b>.
                            </div>
                        </div>
                    </div>
                    <div style="margin-top: 14px; padding-top: 12px; border-top: 1px solid rgba(239, 68, 68, 0.3); font-size: 0.9rem;">
                        <b>Security Policy Action:</b> <span class="metric-chip metric-chip-threat">{res["action"]}</span>
                    </div>
                </div>
                """, unsafe_allow_html=True)
            elif res["bloom_candidate"]:
                st.markdown(f"""
                <div class="verdict-warning">
                    <div style="display: flex; align-items: center; gap: 12px;">
                        <span style="font-size: 2rem;">⚠️</span>
                        <div>
                            <h3 style="margin: 0; color: #f59e0b; font-size: 1.3rem;">BLOOM CANDIDATE • VERIFIED SAFE</h3>
                            <div style="color: #fde68a; font-size: 0.95rem; margin-top: 4px;">
                                Bloom filter flagged a candidate bit match, but exact verification confirmed it is <b>NOT</b> in the threat database (false-positive collision resolved safely).
                            </div>
                        </div>
                    </div>
                    <div style="margin-top: 14px; padding-top: 12px; border-top: 1px solid rgba(245, 158, 11, 0.3); font-size: 0.9rem;">
                        <b>Security Policy Action:</b> <span class="metric-chip metric-chip-safe">{res["action"]}</span>
                    </div>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div class="verdict-safe">
                    <div style="display: flex; align-items: center; gap: 12px;">
                        <span style="font-size: 2rem;">✅</span>
                        <div>
                            <h3 style="margin: 0; color: #10b981; font-size: 1.3rem;">CLEAN INDICATOR • REJECTED BY BLOOM FILTER</h3>
                            <div style="color: #6ee7b7; font-size: 0.95rem; margin-top: 4px;">
                                At least one probed bit was 0. <b>Guaranteed absence</b> from the known threat set in O(k) time without requiring a database query.
                            </div>
                        </div>
                    </div>
                    <div style="margin-top: 14px; padding-top: 12px; border-top: 1px solid rgba(16, 185, 129, 0.3); font-size: 0.9rem;">
                        <b>Security Policy Action:</b> <span class="metric-chip metric-chip-safe">{res["action"]}</span>
                    </div>
                </div>
                """, unsafe_allow_html=True)

            # 3-Stage Pipeline Visualizer
            st.markdown("#### 🔄 Pipeline Execution Visualizer")
            pipe_col1, pipe_col2, pipe_col3 = st.columns(3)

            with pipe_col1:
                st.markdown(f"""
                <div class="pipeline-step">
                    <div class="step-number">Stage 01</div>
                    <div class="step-title">Ingest & Normalize</div>
                    <div style="font-size: 0.85rem; color: #94a3b8; margin-bottom: 8px;">Canonical formatting applied:</div>
                    <div style="background: rgba(0,0,0,0.3); padding: 8px 12px; border-radius: 6px; font-family: monospace; font-size: 0.85rem; color: #38bdf8; word-break: break-all;">
                        {res["normalized"]}
                    </div>
                </div>
                """, unsafe_allow_html=True)

            with pipe_col2:
                b_color = "#f87171" if res["bloom_candidate"] else "#34d399"
                st.markdown(f"""
                <div class="pipeline-step">
                    <div class="step-number">Stage 02</div>
                    <div class="step-title">Bloom Filter Screen</div>
                    <div style="font-size: 0.85rem; color: #94a3b8; margin-bottom: 8px;">Probed {detector.bloom.k} bit positions:</div>
                    <div style="background: rgba(0,0,0,0.3); padding: 8px 12px; border-radius: 6px; font-weight: 700; font-size: 0.9rem; color: {b_color};">
                        {res["bloom_result"]}
                    </div>
                </div>
                """, unsafe_allow_html=True)

            with pipe_col3:
                e_color = "#f87171" if res["exact_match"] else "#34d399"
                st.markdown(f"""
                <div class="pipeline-step">
                    <div class="step-number">Stage 03</div>
                    <div class="step-title">Exact DB & AI Anomaly</div>
                    <div style="font-size: 0.85rem; color: #94a3b8; margin-bottom: 8px;">DB Match & Structural Anomaly:</div>
                    <div style="background: rgba(0,0,0,0.3); padding: 8px 12px; border-radius: 6px; font-weight: 700; font-size: 0.9rem; color: {e_color};">
                        DB: {res["exact_result"]} <br/>
                        <span style="color: {'#f87171' if res['ai_result'] == 'ANOMALOUS' else '#a78bfa'}; font-size: 0.8rem;">
                            AI: {res["ai_result"]}
                        </span>
                    </div>
                </div>
                """, unsafe_allow_html=True)

            # Structural Features Breakdown
            st.markdown("#### 🔬 Structural Feature Analysis")
            f_cols = st.columns(4)
            features = res["features"]
            f_cols[0].metric("Entropy", f"{features['entropy']:.3f}", help="Shannon entropy measures domain randomness")
            f_cols[1].metric("Length", f"{features['length']} chars")
            f_cols[2].metric("Digit Ratio", f"{features['digit_ratio']:.1%}")
            f_cols[3].metric("Subdomains", features['subdomain_count'])

            with st.expander("🔍 View Complete Feature Vector"):
                st.dataframe(pd.DataFrame([features]), use_container_width=True)

# -------------------------------------------------------------
# TAB 2: BATCH SCREENING
# -------------------------------------------------------------
with tab2:
    st.markdown("### Bulk Threat Intelligence Screening")
    st.caption("Screen thousands of indicators simultaneously with high-speed parallel bit screening.")

    batch_col1, batch_col2 = st.columns([3, 1])
    with batch_col1:
        uploaded_file = st.file_uploader(
            "Upload Indicator Feed (CSV format with an `indicator` column)",
            type=["csv"]
        )
    with batch_col2:
        st.markdown("<div style='margin-top: 28px;'></div>", unsafe_allow_html=True)
        load_demo_batch = st.button("⚡ Load Demo Feed (sample_scan.csv)", use_container_width=True)

    df_to_scan = None
    if uploaded_file:
        df_to_scan = pd.read_csv(uploaded_file)
    elif load_demo_batch:
        df_to_scan = pd.read_csv("data/sample_scan.csv")

    if df_to_scan is not None:
        if "indicator" not in df_to_scan.columns:
            st.error("Uploaded CSV must contain an `indicator` column.")
        else:
            with st.spinner("Processing batch through BloomShield pipeline..."):
                raw_indicators = df_to_scan["indicator"].astype(str).tolist()
                results = detector.batch_scan(raw_indicators)
                res_df = pd.DataFrame(results)

            # Summary Metrics Row
            total_cnt = len(res_df)
            threat_cnt = int(res_df["exact_match"].sum())
            anomaly_cnt = int((res_df["ai_result"] == "ANOMALOUS").sum())
            clean_cnt = total_cnt - threat_cnt

            kpi1, kpi2, kpi3, kpi4 = st.columns(4)
            kpi1.metric("Total Indicators", f"{total_cnt:,}")
            kpi2.metric("Threats Quarantined", f"{threat_cnt:,}", delta=f"{threat_cnt/total_cnt:.1%}" if total_cnt else None, delta_color="inverse")
            kpi3.metric("Clean Allowed", f"{clean_cnt:,}")
            kpi4.metric("AI Anomalies", f"{anomaly_cnt:,}", help="Indicators flagged as structurally atypical")

            # Formatted Results Table
            st.markdown("#### Screening Results")
            display_df = res_df[["indicator", "normalized", "bloom_result", "exact_result", "ai_result", "action"]].copy()
            st.dataframe(display_df, use_container_width=True)

            # Download Option
            csv_data = res_df.to_csv(index=False).encode("utf-8")
            st.download_button(
                label="📥 Export Scan Report (CSV)",
                data=csv_data,
                file_name="bloomshield_threat_report.csv",
                mime="text/csv",
                type="primary"
            )

# -------------------------------------------------------------
# TAB 3: AI ANOMALY ENGINE
# -------------------------------------------------------------
with tab3:
    st.markdown("### Structural Anomaly Detection Engine")
    st.markdown("""
    The AI layer extracts structural and lexical features from domain names, URLs, and network entities to detect 
    **Domain Generation Algorithms (DGA)**, zero-day phishing patterns, and abnormal URL paths using an **Isolation Forest**.
    """)

    ai_input = st.text_input(
        "Indicator for Deep AI Inspection",
        value="xj3k9q8z1m7v4p2n6a5s9d8f0g3h1j7k.example",
        placeholder="Enter URL, DGA domain, or host"
    )

    if st.button("🧠 Compute Anomaly Score", type="primary"):
        if ai_input.strip():
            ai_res = detector.ai_analyze(ai_input)
            
            ai_c1, ai_c2, ai_c3 = st.columns(3)
            is_anom = ai_res["prediction"] == "ANOMALOUS"
            ai_c1.metric("AI Verdict", ai_res["prediction"], delta="Flagged" if is_anom else "Normal", delta_color="inverse" if is_anom else "normal")
            ai_c2.metric("Anomaly Score", f"{ai_res['score']:.4f}", help="Scores below 0 indicate deviation from training distribution")
            ai_c3.metric("Model Architecture", "Isolation Forest (200 trees)")

            if is_anom:
                st.markdown("""
                <div class="verdict-threat" style="padding: 16px;">
                    ⚠️ <b>AI Signal:</b> Indicator exhibits statistically abnormal lexical properties (e.g. elevated Shannon entropy, unusual character distributions, or abnormal label lengths) typical of algorithmically generated domains (DGAs).
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown("""
                <div class="verdict-safe" style="padding: 16px;">
                    ✅ <b>AI Signal:</b> Indicator's lexical profile aligns with legitimate enterprise web patterns.
                </div>
                """, unsafe_allow_html=True)

            st.markdown("#### Feature Importance & Vector")
            st.json(ai_res["features"])

# -------------------------------------------------------------
# TAB 4: BLOOM FILTER THEORY & LAB
# -------------------------------------------------------------
with tab4:
    st.markdown("### 📊 Bloom Filter Mathematics & Interactive Lab")
    st.markdown("""
    A Bloom filter is a space-efficient probabilistic data structure used to test set membership in $O(k)$ time.
    It guarantees **zero false negatives**: if an indicator was inserted, the filter will **never** report it as absent.
    """)

    col_t1, col_t2 = st.columns([1, 1])

    with col_t1:
        st.markdown("#### ⚙️ Interactive Parameter Simulator")
        sim_n = st.slider("Number of Inserted Threats (n)", min_value=10, max_value=5000, value=len(detector.threat_set), step=10)
        sim_bpi = st.slider("Bits per Item (m / n)", min_value=4, max_value=24, value=12, step=1)
        sim_m = sim_n * sim_bpi
        optimal_k = max(1, round(sim_bpi * math.log(2)))
        sim_k = st.slider("Number of Hash Functions (k)", min_value=1, max_value=16, value=optimal_k)

        # Theoretical False Positive Rate
        sim_fp = (1 - math.exp(-sim_k * sim_n / sim_m)) ** sim_k

        st.metric("Estimated False-Positive Probability", f"{sim_fp:.4%}", delta="Optimal k chosen" if sim_k == optimal_k else f"Optimal k = {optimal_k}")
        st.caption(f"Bit Array Size (m): **{sim_m:,} bits** (~{sim_m/8/1024:.2f} KB)")

    with col_t2:
        st.markdown("#### 📐 Mathematical Formulations")
        st.latex(r"p \approx \left(1 - e^{-kn/m}\right)^k")
        st.latex(r"k_{\text{optimal}} = \frac{m}{n} \ln 2 \approx 0.693 \cdot \frac{m}{n}")

        st.markdown("""
        <div class="cyber-card" style="margin-top: 20px;">
            <div style="font-weight: 700; color: #818cf8; margin-bottom: 6px;">Key Guarantees:</div>
            <ul style="color: #cbd5e1; font-size: 0.9rem; margin-bottom: 0;">
                <li><b>No False Negatives:</b> Legitimate threats are never erroneously cleared by the Bloom filter.</li>
                <li><b>Constant Time Complexity:</b> Membership testing executes in strict $O(k)$ time.</li>
                <li><b>Privacy Preserving:</b> Original threat indicators cannot be reversed from the bit array.</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("#### ⚡ Algorithmic Specification")
    st.code(
        "INSERT(x):\n"
        "    for each hash function i = 1..k:\n"
        "        bit_index = (hash_1(x) + i * hash_2(x)) mod m\n"
        "        bit_array[bit_index] = 1\n\n"
        "QUERY(x):\n"
        "    for each hash function i = 1..k:\n"
        "        bit_index = (hash_1(x) + i * hash_2(x)) mod m\n"
        "        if bit_array[bit_index] == 0:\n"
        "            return DEFINITELY_NOT_PRESENT   // Guaranteed safe\n"
        "    return POSSIBLY_PRESENT                  // Requires exact verification",
        language="python"
    )

st.markdown("""
<div style="text-align: center; color: #64748b; font-size: 0.8rem; margin-top: 40px; padding-top: 20px; border-top: 1px solid rgba(255,255,255,0.05);">
    BloomShield Cybersecurity Research Prototype • Advanced Algorithmic Threat Intelligence • CSE533
</div>
""", unsafe_allow_html=True)

# dashboard.py
import streamlit as st
from quantumguard.utils.config import config
import json
from pathlib import Path
import networkx as nx
from quantumguard.utils.viz import plot_threat_graph

# ────────────────────────────────────────────────
# Page config
# ────────────────────────────────────────────────

st.set_page_config(
    page_title="QuantumGuard AI Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.title("🛡️ QuantumGuard AI Dashboard")
st.caption(f"Environment: {config().app.environment} | Log level: {config().app.log_level}")

# ────────────────────────────────────────────────
# Sidebar
# ────────────────────────────────────────────────

with st.sidebar:
    st.header("Controls")
    run_detect = st.button("Run Dummy Detect", type="primary")
    st.markdown("---")
    st.info("Dashboard MVP — real data & GNN coming soon")

# ────────────────────────────────────────────────
# Main content tabs
# ────────────────────────────────────────────────

tab1, tab2, tab3 = st.tabs(["Overview", "Detection", "Graph"])

with tab1:
    st.subheader("System Status")
    col1, col2 = st.columns(2)
    col1.metric("Environment", config().app.environment)
    col2.metric("Log Level", config().app.log_level)

    st.markdown("### Quick Stats")
    st.write("- Agents ready: ThreatDetector, ResponseEngine")
    st.write("- Last GNN model: GraphSAGE (dummy)")
    st.write("- Graph saved: outputs/detect_graph.html")

with tab2:
    st.subheader("Run Detection")
    if run_detect:
        with st.spinner("Running dummy detection..."):
            # Simulate your CLI detect output
            st.success("Detection complete!")
            st.write("Anomaly score: **0.87** (dummy)")
            st.write("Top suspicious nodes:")
            st.write("- 192.168.1.100")
            st.write("- 10.0.0.5")
            st.write("High confidence alert: **Triggered**")
            st.write("Environment:", config().app.environment)

            # Show summary table
            data = {
                "Metric": ["Status", "Anomaly Score", "High Confidence", "Nodes Analyzed", "Execution Time"],
                "Value": ["success", "0.000", "False", "0", "0.001s"]
            }
            st.table(data)

with tab3:
    st.subheader("Threat Graph")
    graph_file = Path("outputs/detect_graph.html")

    if graph_file.exists():
        st.success("Graph found!")
        # Option 1: Link to open in new tab
        st.markdown(f"[Open interactive graph]({graph_file})", unsafe_allow_html=True)

        # Option 2: Embed (may not always work perfectly in Streamlit)
        try:
            with open(graph_file, "r", encoding="utf-8") as f:
                html_content = f.read()
            st.components.v1.html(html_content, height=600, scrolling=True)
        except Exception as e:
            st.warning(f"Could not embed graph: {e}")
    else:
        st.warning("No graph found yet. Run detect command first.")

st.markdown("---")
st.caption("QuantumGuard AI v0.1.0-dev | MIT License (open core)")

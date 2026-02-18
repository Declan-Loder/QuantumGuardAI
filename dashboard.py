# dashboard.py
import streamlit as st
import subprocess
from pathlib import Path
import time
from quantumguard.utils.config import config

# ────────────────────────────────────────────────
# Page config with octopus 🐙
# ────────────────────────────────────────────────

st.set_page_config(
    page_title="QuantumGuard AI 🐙",
    page_icon="🐙",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.title("🐙 QuantumGuard AI Dashboard")
st.caption(f"v0.1.0-dev | Environment: {config().app.environment} | Log level: {config().app.log_level}")

# ────────────────────────────────────────────────
# Sidebar Controls
# ────────────────────────────────────────────────

with st.sidebar:
    st.header("Controls")
    
    col1, col2 = st.columns(2)
    with col1:
        run_detect = st.button("Run Detect", type="primary", use_container_width=True)
    with col2:
        refresh = st.button("Refresh", use_container_width=True)

    st.markdown("---")
    st.info("🐙 MVP Dashboard — real GNN & alerts coming soon")

# ────────────────────────────────────────────────
# Main Tabs
# ────────────────────────────────────────────────

tab1, tab2, tab3 = st.tabs(["🐙 Overview", "Detection", "Graph"])

# ────────────────────────────────────────────────
# Overview Tab
# ────────────────────────────────────────────────

with tab1:
    st.subheader("System Status")
    
    col1, col2, col3 = st.columns(3)
    col1.metric("Environment", config().app.environment, delta_color="normal")
    col2.metric("Log Level", config().app.log_level)
    col3.metric("Last Detection", time.strftime("%H:%M:%S"), delta="Just now" if run_detect else "Never")

    st.markdown("### Quick Stats")
    st.markdown("- Agents ready: ThreatDetector, ResponseEngine")
    st.markdown("- Last GNN model: GraphSAGE (dummy)")
    st.markdown("- Graph saved: outputs/detect_graph.html")

    if st.button("Clear Cache & Restart"):
        st.cache_data.clear()
        st.rerun()

# ────────────────────────────────────────────────
# Detection Tab
# ────────────────────────────────────────────────

with tab2:
    st.subheader("Latest Detection")
    
    if run_detect or refresh:
        with st.spinner("Running detection..."):
            try:
                # Run the real CLI command
                result = subprocess.run(
                    ["poetry", "run", "quantumguard", "detect", "data/dummy_logs.json"],
                    capture_output=True,
                    text=True,
                    timeout=60  # 60 seconds max
                )

                if result.returncode == 0:
                    st.success("Detection complete!")
                    
                    # Show output in expandable code block
                    with st.expander("Full Detection Output", expanded=True):
                        st.code(result.stdout, language="text")
                    
                    # Try to parse the summary table from output (simple string search)
                    if "Detection Summary" in result.stdout:
                        st.markdown("### Detection Summary")
                        # Very basic parsing - you can improve later
                        lines = result.stdout.splitlines()
                        for line in lines:
                            if "│" in line and "Metric" not in line and "Value" not in line:
                                st.write(line.strip())
                else:
                    st.error("Detection failed")
                    st.code(result.stderr, language="text")
                    
            except subprocess.TimeoutExpired:
                st.error("Detection timed out after 60 seconds")
            except Exception as e:
                st.error(f"Error running detect: {e}")
    else:
        st.info("Click 'Run Detect' to scan logs and generate a graph")

# ────────────────────────────────────────────────
# Graph Tab
# ────────────────────────────────────────────────

with tab3:
    st.subheader("Threat Graph")
    graph_file = Path("outputs/detect_graph.html")

    if graph_file.exists():
        st.success(f"Graph found ({graph_file.stat().st_size / 1024:.1f} KB)")
        
        # Link to open in new tab
        st.markdown(f"[🌐 Open interactive graph in new tab]({graph_file})", unsafe_allow_html=True)
        
        # Embed the Plotly HTML (usually works great)
        try:
            with open(graph_file, "r", encoding="utf-8") as f:
                html_content = f.read()
            st.components.v1.html(html_content, height=700, scrolling=True)
        except Exception as e:
            st.warning(f"Could not embed graph: {e} — use the link above")
    else:
        st.warning("No graph yet. Run detection first to generate one.")

st.markdown("---")
st.caption("🐙 QuantumGuard AI — Privacy-preserving, self-optimizing cybersecurity")
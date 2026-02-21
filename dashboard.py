# dashboard.py
import streamlit as st
import subprocess
from pathlib import Path
import time
from quantumguard.utils.config import config
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from io import BytesIO

# Direct imports for optimizer (faster than subprocess)
from quantumguard.agents.threat_detector import ThreatDetector
from quantumguard.agents.optimizer import Optimizer
from quantumguard.tools.log_analyzer import LogAnalyzer
import networkx as nx

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
    
    col1, col2, col3 = st.columns(3)
    with col1:
        run_detect = st.button("Run Detect", type="primary", use_container_width=True)
    with col2:
        refresh = st.button("Refresh", use_container_width=True)
    with col3:
        run_optimize = st.button("Run Optimization", use_container_width=True)

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
    col1.metric("Environment", config().app.environment)
    col2.metric("Log Level", config().app.log_level)
    col3.metric("Last Detection", time.strftime("%H:%M:%S"), delta="Just now" if run_detect else "Never")

    st.markdown("### Quick Stats")
    st.markdown("- Agents ready: ThreatDetector, ResponseEngine, Optimizer")
    st.markdown("- Last GNN model: GraphSAGE (dummy)")
    st.markdown("- Graph saved: outputs/detect_graph.html")

# ────────────────────────────────────────────────
# Detection Tab (with PDF download)
# ────────────────────────────────────────────────

with tab2:
    st.subheader("Latest Detection")
    
    if run_detect or refresh:
        with st.spinner("🐙 Scanning for threats..."):
            try:
                # Direct call instead of subprocess (much faster)
                cfg = config().agents.threat_detector
                detector = ThreatDetector("dashboard-detector", config=cfg.dict())

                analyzer = LogAnalyzer(config().tools.log_analyzer)
                events = analyzer.parse_log_file(Path("data/dummy_logs.json"))

                graph = nx.Graph()
                for event in events:
                    src = event.get("src_ip")
                    dst = event.get("dst_ip")
                    if src and dst and src != dst:
                        graph.add_node(src, type="device")
                        graph.add_node(dst, type="device")
                        graph.add_edge(src, dst,
                                       protocol=event.get("protocol", "unknown"),
                                       bytes=event.get("bytes_in", 0) + event.get("bytes_out", 0),
                                       anomaly=event.get("anomaly", False))

                result = detector.execute(graph)

                st.success("Detection complete!")

                # Show summary table
                table_data = [
                    ["Status", result["status"]],
                    ["Anomaly Score", f"{result['detection_result']['anomaly_score']:.3f}"],
                    ["High Confidence", str(result["high_confidence"])],
                    ["Nodes Analyzed", str(result["graph_nodes"])],
                    ["Execution Time", f"{result['execution_time_seconds']}s"],
                ]
                st.table(table_data)

                # Suspicious IPs
                suspicious_ips = result.get("suspicious_ips", [])
                if suspicious_ips:
                    st.markdown("### Suspicious IPs Detected")
                    for ip in suspicious_ips:
                        st.write(f"- {ip}")

                # PDF Download
                def create_pdf():
                    buffer = BytesIO()
                    c = canvas.Canvas(buffer, pagesize=letter)
                    width, height = letter

                    c.setFont("Helvetica-Bold", 16)
                    c.drawCentredString(width/2, height - 80, "QuantumGuard AI Detection Report")
                    c.setFont("Helvetica", 12)
                    c.drawCentredString(width/2, height - 110, f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}")

                    y = height - 160
                    c.setFont("Helvetica-Bold", 12)
                    c.drawString(100, y, "Summary")
                    c.setFont("Helvetica", 12)
                    y -= 30
                    c.drawString(120, y, f"Environment: {config().app.environment}")
                    y -= 20
                    c.drawString(120, y, f"Anomaly Score: {result['detection_result']['anomaly_score']:.3f}")
                    y -= 20
                    c.drawString(120, y, f"High Confidence: {result['high_confidence']}")
                    y -= 20
                    c.drawString(120, y, f"Nodes Analyzed: {result['graph_nodes']}")
                    y -= 40

                    c.setFont("Helvetica-Bold", 12)
                    c.drawString(100, y, "Suspicious IPs")
                    c.setFont("Helvetica", 12)
                    y -= 30
                    if suspicious_ips:
                        for ip in suspicious_ips:
                            c.drawString(120, y, f"- {ip}")
                            y -= 20
                    else:
                        c.drawString(120, y, "- None detected")

                    c.save()
                    buffer.seek(0)
                    return buffer

                pdf_buffer = create_pdf()
                st.download_button(
                    label="Download PDF Report",
                    data=pdf_buffer,
                    file_name=f"quantumguard_report_{time.strftime('%Y%m%d_%H%M')}.pdf",
                    mime="application/pdf"
                )

            except Exception as e:
                st.error(f"Error running detection: {e}")
    else:
        st.info("Click 'Run Detect' to scan logs and generate a report")

# ────────────────────────────────────────────────
# Optimization Results (triggered from sidebar button)
# ────────────────────────────────────────────────

if run_optimize:
    with st.spinner("Optimizing system..."):
        try:
            cfg = config().agents.optimizer
            optimizer = Optimizer("dashboard-optimizer", config=cfg.dict())

            result = optimizer.execute()

            with st.expander("Optimization Results", expanded=True):
                st.success("Optimization cycle complete!")
                st.markdown(f"**Improved:** {result.get('improved', 'N/A')}")
                st.markdown(f"**Message:** {result.get('message', 'No change')}")
                st.markdown(f"**Old threshold:** {result.get('old_threshold', 'N/A'):.3f}")
                st.markdown(f"**New threshold:** {result.get('new_threshold', 'N/A'):.3f}")
                st.markdown(f"**High-confidence ratio:** {result.get('high_confidence_ratio', 'N/A')}")
                st.markdown(f"**History entries analyzed:** {result.get('history_count', 0)}")

        except Exception as e:
            st.error(f"Optimization failed: {e}")

# ────────────────────────────────────────────────
# Graph Tab
# ────────────────────────────────────────────────

with tab3:
    st.subheader("Threat Graph")
    graph_file = Path("outputs/detect_graph.html")

    if graph_file.exists():
        st.success(f"Graph found ({graph_file.stat().st_size / 1024:.1f} KB)")
        st.markdown(f"[🌐 Open interactive graph in new tab]({graph_file})", unsafe_allow_html=True)
        
        try:
            with open(graph_file, "r", encoding="utf-8") as f:
                html = f.read()
            st.components.v1.html(html, height=700, scrolling=True)
        except Exception as e:
            st.warning(f"Embed failed: {e} — use the link above")
    else:
        st.warning("No graph yet. Run detection first to generate one.")

st.markdown("---")
st.caption("🐙 QuantumGuard AI — Privacy-preserving, self-optimizing cybersecurity")
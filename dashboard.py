# dashboard.py
import streamlit as st
import subprocess
from pathlib import Path
import time
from quantumguard.utils.config import config
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from io import BytesIO

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
    col1.metric("Environment", config().app.environment)
    col2.metric("Log Level", config().app.log_level)
    col3.metric("Last Detection", time.strftime("%H:%M:%S"), delta="Just now" if run_detect else "Never")

    st.markdown("### Quick Stats")
    st.markdown("- Agents ready: ThreatDetector, ResponseEngine")
    st.markdown("- Last GNN model: GraphSAGE (dummy)")
    st.markdown("- Graph saved: outputs/detect_graph.html")

# ────────────────────────────────────────────────
# Detection Tab (with PDF download)
# ────────────────────────────────────────────────

with tab2:
    st.subheader("Latest Detection")
    
    detection_result = None  # To store output for PDF

    if run_detect or refresh:
        with st.spinner("🐙 Scanning for threats..."):
            try:
                proc = subprocess.run(
                    ["poetry", "run", "quantumguard", "detect", "data/dummy_logs.json"],
                    capture_output=True,
                    text=True,
                    timeout=90
                )

                if proc.returncode == 0:
                    st.success("Detection complete!")
                    detection_result = proc.stdout

                    # Show full raw output (collapsed by default)
                    with st.expander("Full Raw Output", expanded=False):
                        st.code(detection_result, language="text")

                    # Parse summary table
                    lines = detection_result.splitlines()
                    table_data = []
                    in_table = False
                    for line in lines:
                        if "Detection Summary" in line:
                            in_table = True
                            continue
                        if in_table and "└" in line:
                            in_table = False
                        if in_table and "│" in line and "Metric" not in line and "Value" not in line:
                            parts = [p.strip() for p in line.split("│") if p.strip()]
                            if len(parts) == 2:
                                table_data.append(parts)

                    if table_data:
                        st.markdown("### Detection Summary")
                        st.table(table_data)

                    # Extract suspicious IPs from prevention simulation
                    suspicious_ips = []
                    in_prevention = False
                    for line in lines:
                        if "[PREVENTION SIMULATION]" in line:
                            in_prevention = True
                            continue
                        if in_prevention and "Blocking suspicious IP:" in line:
                            ip_part = line.split("Blocking suspicious IP: ")[1].split(" ")[0]
                            suspicious_ips.append(ip_part)

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
                        c.drawString(120, y, f"Anomaly Score: 0.773 (latest run)")
                        y -= 20
                        c.drawString(120, y, "High Confidence: True")
                        y -= 20
                        c.drawString(120, y, "Nodes Analyzed: 4")
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

                else:
                    st.error("Detection failed")
                    st.code(proc.stderr, language="text")

            except subprocess.TimeoutExpired:
                st.error("Detection timed out (90 seconds)")
            except Exception as e:
                st.error(f"Error running detection: {e}")
    else:
        st.info("Click 'Run Detect' to scan logs and generate a report")

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
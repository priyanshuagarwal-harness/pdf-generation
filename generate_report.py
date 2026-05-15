#!/usr/bin/env python3
import json
import os
from datetime import datetime, timezone
from fpdf import FPDF


def sanitize(text):
    """Replace Unicode characters with ASCII equivalents for fpdf core fonts."""
    replacements = {
        '—': '--',  # em dash
        '–': '-',   # en dash
        '‘': "'",   # left single quote
        '’': "'",   # right single quote
        '“': '"',   # left double quote
        '”': '"',   # right double quote
        '…': '...',  # ellipsis
        '•': '*',   # bullet
        '×': 'x',  # multiplication sign
        '≥': '>=',  # >=
        '≤': '<=',  # <=
        '·': '.',   # middle dot
    }
    for char, repl in replacements.items():
        text = text.replace(char, repl)
    return text.encode('latin-1', errors='replace').decode('latin-1')

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
JSON_PATH = os.path.join(SCRIPT_DIR, "referenceFile", "scan-report.json")
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "results")
OUTPUT_PDF = os.path.join(OUTPUT_DIR, "passive-risk-detection-report.pdf")

with open(JSON_PATH, "r") as f:
    data = json.load(f)

scan = data["scan"]
risks = data["scannedRisks"]
summary = data["summary"]

scan_name = scan["name"]
scan_date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
account_id = scan["accountID"]
org_id = scan["orgID"]
project_id = scan["projectID"]
cluster = scan["spec"]["sourceIdentity"]["cluster"]
namespace = scan["spec"]["sourceIdentity"]["namespace"]
scan_identity = scan["identity"]

total_risks = summary["totalRisks"]
high_count = summary["bySeverity"].get("High", 0)
medium_count = summary["bySeverity"].get("Medium", 0)
low_count = summary["bySeverity"].get("Low", 0)
open_count = summary["byStatus"].get("Open", 0)

target_services = set()
for risk in risks:
    tp = risk.get("metadata", {}).get("targetPrincipal", {})
    ident = tp.get("identification", {})
    name = ident.get("name", "")
    if name:
        target_services.add(name)

risk_score = high_count * 10 + medium_count * 4 + low_count * 1


class PDFReport(FPDF):
    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=25)

    def cell(self, w=0, h=None, text="", *args, **kwargs):
        return super().cell(w, h, sanitize(str(text)) if text else "", *args, **kwargs)

    def multi_cell(self, w, h=None, text="", *args, **kwargs):
        return super().multi_cell(w, h, sanitize(str(text)) if text else "", *args, **kwargs)

    def header(self):
        if self.page_no() > 1:
            self.set_font("Helvetica", "B", 8)
            self.set_text_color(100, 100, 100)
            self.cell(0, 5, f"Passive Risk Detection Report | {project_id} | Harness CD | Scanned {scan_date}", align="L")
            self.ln(3)
            self.set_draw_color(200, 200, 200)
            self.line(10, self.get_y(), 200, self.get_y())
            self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "", 7)
        self.set_text_color(150, 150, 150)
        self.set_draw_color(180, 180, 180)
        self.line(10, self.get_y() - 3, 200, self.get_y() - 3)
        footer_text = f"PRD-REPORT | PASSIVE RISK DETECTION | {project_id} | {scan_date} | HARNESS RESILIENCE TESTING -- EXPERIMENTAL | Confidential"
        self.cell(0, 10, footer_text, align="L")
        self.cell(0, 10, f"Page {self.page_no()}", align="R")

    def section_title(self, number, title):
        self.set_font("Helvetica", "B", 18)
        self.set_text_color(44, 62, 80)
        self.set_fill_color(44, 62, 80)
        self.rect(10, self.get_y(), 3, 8, "F")
        self.cell(8, 8, "")
        self.cell(0, 8, f"{number} . {title}", ln=True)
        self.ln(3)

    def draw_summary_box(self, x, w, value, label, r, g, b):
        y = self.get_y()
        h = 30
        self.set_fill_color(r, g, b)
        self.rect(x, y, w, h, "F")
        self.set_xy(x, y + 4)
        self.set_font("Helvetica", "B", 18)
        self.set_text_color(255, 255, 255)
        self.cell(w, 10, str(value), align="C")
        self.set_xy(x, y + 16)
        self.set_font("Helvetica", "", 7)
        self.set_text_color(230, 230, 230)
        self.cell(w, 6, label.upper(), align="C")


pdf = PDFReport()
pdf.set_margins(10, 10, 10)
os.makedirs(OUTPUT_DIR, exist_ok=True)

# --- PAGE 1: COVER & EXECUTIVE SUMMARY ---
pdf.add_page()

# Title
pdf.set_font("Helvetica", "B", 26)
pdf.set_text_color(44, 62, 80)
pdf.cell(0, 12, "Passive Risk Detection Report", ln=True)
pdf.ln(2)

# Subtitle
pdf.set_font("Helvetica", "", 11)
pdf.set_text_color(80, 80, 80)
pdf.cell(0, 5, f"{project_id}  .  Harness CD  .  Cluster: {cluster}  .  Namespace: {namespace}", ln=True)
pdf.set_font("Helvetica", "", 9)
pdf.cell(0, 5, f"Scan Identity: {scan_identity}  .  Scanned {scan_date}", ln=True)
pdf.ln(1)
pdf.set_font("Helvetica", "B", 9)
pdf.set_text_color(192, 57, 43)
pdf.cell(0, 5, "HARNESS RESILIENCE TESTING -- EXPERIMENTAL | Confidential", ln=True)
pdf.ln(8)

# Section 1
pdf.section_title("1", "Executive Summary")
pdf.ln(2)

# Summary boxes
box_w = 36
start_x = 12
y_before = pdf.get_y()

pdf.draw_summary_box(start_x, box_w, f"{risk_score}/1000", "Pipeline Risk Score", 44, 62, 80)
pdf.draw_summary_box(start_x + box_w + 2, box_w, str(high_count), "High Risks", 192, 57, 43)
pdf.draw_summary_box(start_x + 2*(box_w + 2), box_w, str(medium_count), "Medium Risks", 230, 126, 34)
pdf.draw_summary_box(start_x + 3*(box_w + 2), box_w, str(low_count), "Low Risks", 41, 128, 185)
pdf.draw_summary_box(start_x + 4*(box_w + 2), box_w, str(total_risks), "Total Risks", 39, 174, 96)

pdf.set_y(y_before + 35)

# Description paragraph
pdf.set_font("Helvetica", "", 10)
pdf.set_text_color(60, 60, 60)
pdf.multi_cell(0, 5,
    f"This report presents the results of a passive resilience risk scan performed by the Harness Resilience "
    f"Testing engine against Harness CD pipeline for project {project_id}. The scan targeted "
    f"cluster {cluster} in namespace {namespace}. No code changes, instrumentation, or manual "
    f"configuration were required -- the engine scanned Harness CD metadata, Kubernetes manifests, "
    f"and deployment configuration only.")
pdf.ln(3)
pdf.multi_cell(0, 5,
    f"The scan identified {high_count} HIGH-severity risks and {medium_count} MEDIUM-severity risks "
    f"across {len(target_services)} service(s). All {total_risks} risks are currently in Open status "
    f"with no chaos or load tests covering them -- a critical coverage gap.")
pdf.ln(5)

# Metrics table
metrics = [
    ("Metric", "Value", "Detail"),
    ("Services Scanned", str(len(target_services)), f"Deployment in namespace: {namespace}"),
    ("Total Risks Detected", str(total_risks), f"High: {high_count}, Medium: {medium_count}, Low: {low_count}"),
    ("Services Affected", str(len(target_services)), ", ".join(sorted(target_services))),
    ("Chaos Test Coverage", f"0/{len(target_services)}", "100% uncovered -- no resilience validation"),
    ("Open Risks", str(open_count), "All risks remain unresolved"),
    ("Scan Type", scan["spec"]["scanType"], "Passive metadata-only analysis"),
]

col_widths = [55, 30, 105]
for i, row in enumerate(metrics):
    if i == 0:
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_fill_color(52, 73, 94)
        pdf.set_text_color(255, 255, 255)
    else:
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(50, 50, 50)
        if i % 2 == 0:
            pdf.set_fill_color(249, 249, 249)
        else:
            pdf.set_fill_color(255, 255, 255)
    for j, val in enumerate(row):
        if i > 0 and j == 0:
            pdf.set_font("Helvetica", "B", 9)
        elif i > 0:
            pdf.set_font("Helvetica", "", 9)
        pdf.cell(col_widths[j], 8, val, border=1, fill=True)
    pdf.ln()

# --- PAGE 2: SERVICES FOUND ---
pdf.add_page()
pdf.section_title("2", "Services Found in Pipeline")
pdf.ln(2)

pdf.set_font("Helvetica", "", 10)
pdf.set_text_color(60, 60, 60)
pdf.multi_cell(0, 5, "All services in the target namespace were passively scanned -- no code changes, instrumentation, or manual configuration required.")
pdf.ln(5)

# Services table
svc_headers = ["Service", "Total Risks", "High", "Medium", "Low", "RRS"]
svc_col_w = [40, 25, 25, 25, 25, 25]

pdf.set_font("Helvetica", "B", 9)
pdf.set_fill_color(52, 73, 94)
pdf.set_text_color(255, 255, 255)
for j, h in enumerate(svc_headers):
    pdf.cell(svc_col_w[j], 8, h, border=1, fill=True, align="C")
pdf.ln()

for svc in sorted(target_services):
    service_risks = [r for r in risks if r.get("metadata", {}).get("targetPrincipal", {}).get("identification", {}).get("name") == svc]
    s_high = sum(1 for r in service_risks if r["severity"] == "High")
    s_med = sum(1 for r in service_risks if r["severity"] == "Medium")
    s_low = sum(1 for r in service_risks if r["severity"] == "Low")
    s_total = len(service_risks)
    rrs = s_high * 10 + s_med * 4 + s_low * 1

    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(44, 62, 80)
    pdf.set_fill_color(255, 255, 255)
    pdf.cell(svc_col_w[0], 8, svc, border=1, fill=True)

    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(50, 50, 50)
    pdf.cell(svc_col_w[1], 8, str(s_total), border=1, align="C")

    pdf.set_text_color(192, 57, 43)
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(svc_col_w[2], 8, str(s_high) if s_high > 0 else "--", border=1, align="C")

    pdf.set_text_color(230, 126, 34)
    pdf.cell(svc_col_w[3], 8, str(s_med) if s_med > 0 else "--", border=1, align="C")

    pdf.set_text_color(41, 128, 185)
    pdf.cell(svc_col_w[4], 8, str(s_low) if s_low > 0 else "--", border=1, align="C")

    rrs_color = (192, 57, 43) if rrs >= 30 else (230, 126, 34) if rrs >= 15 else (41, 128, 185)
    pdf.set_text_color(*rrs_color)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(svc_col_w[5], 8, str(rrs), border=1, align="C")
    pdf.ln()

# Total row
pdf.set_font("Helvetica", "B", 9)
pdf.set_fill_color(52, 73, 94)
pdf.set_text_color(255, 255, 255)
pdf.cell(svc_col_w[0], 8, f"TOTAL ({len(target_services)} svc)", border=1, fill=True)
pdf.cell(svc_col_w[1], 8, str(total_risks), border=1, fill=True, align="C")
pdf.set_text_color(255, 107, 107)
pdf.cell(svc_col_w[2], 8, str(high_count), border=1, fill=True, align="C")
pdf.set_text_color(254, 202, 87)
pdf.cell(svc_col_w[3], 8, str(medium_count), border=1, fill=True, align="C")
pdf.set_text_color(72, 219, 251)
pdf.cell(svc_col_w[4], 8, str(low_count), border=1, fill=True, align="C")
pdf.set_text_color(255, 255, 255)
pdf.cell(svc_col_w[5], 8, str(risk_score), border=1, fill=True, align="C")
pdf.ln(10)

pdf.set_font("Helvetica", "I", 8)
pdf.set_text_color(130, 130, 130)
pdf.multi_cell(0, 4, "* RRS = HIGH x 10 + MEDIUM x 4 + LOW x 1. Critical (>=30): immediate action required. High (15-29): near-term attention. Medium (<15): best-practice deviation.")

# --- PAGE 3: RISKS FOUND ---
pdf.add_page()
pdf.section_title("3", "Risks Found")
pdf.ln(2)

pdf.set_font("Helvetica", "", 10)
pdf.set_text_color(60, 60, 60)
pdf.multi_cell(0, 5, f"{total_risks} risks detected across {len(target_services)} service(s) -- {high_count} HIGH . {medium_count} MEDIUM . {low_count} LOW. Each risk listed with description and affected services.")
pdf.ln(5)

severity_colors = {
    "High": (192, 57, 43),
    "Medium": (230, 126, 34),
    "Low": (41, 128, 185),
}

severity_bg = {
    "High": (253, 236, 234),
    "Medium": (254, 249, 231),
    "Low": (234, 242, 248),
}

for risk in risks:
    sev = risk["severity"]
    color = severity_colors.get(sev, (50, 50, 50))
    bg = severity_bg.get(sev, (255, 255, 255))
    tp = risk.get("metadata", {}).get("targetPrincipal", {})
    ident = tp.get("identification", {})
    target_name = ident.get("name", "N/A")
    target_ns = ident.get("namespace", "N/A")
    principal_type = tp.get("principalType", "N/A")
    impact = risk.get("metadata", {}).get("impact", "")

    if pdf.get_y() > 230:
        pdf.add_page()

    card_y = pdf.get_y()
    pdf.set_fill_color(*bg)
    pdf.rect(10, card_y, 190, 2, "F")

    # Severity bar on left
    pdf.set_fill_color(*color)
    pdf.rect(10, card_y, 3, 45, "F")

    # Background fill
    pdf.set_fill_color(*bg)
    pdf.rect(13, card_y, 187, 45, "F")

    # Severity badge + name
    pdf.set_xy(16, card_y + 3)
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_fill_color(*color)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(18, 5, sev.upper(), fill=True, align="C")

    pdf.set_xy(37, card_y + 3)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(44, 62, 80)
    pdf.cell(0, 5, risk["name"])

    # Description
    pdf.set_xy(16, card_y + 11)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(60, 60, 60)
    pdf.multi_cell(180, 4, risk["description"])

    # Target info
    desc_end_y = pdf.get_y()
    pdf.set_xy(16, desc_end_y + 1)
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 4, f"Affects: {principal_type}/{target_name} in namespace {target_ns}")

    # Impact
    pdf.set_xy(16, desc_end_y + 5)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(80, 80, 80)
    impact_short = impact[:150] + "..." if len(impact) > 150 else impact
    pdf.multi_cell(180, 3.5, f"Impact: {impact_short}")

    # Tags
    tag_y = pdf.get_y() + 1
    pdf.set_xy(16, tag_y)
    pdf.set_font("Helvetica", "", 7)
    for tag in risk.get("tags", []):
        pdf.set_fill_color(236, 240, 241)
        pdf.set_text_color(80, 80, 80)
        tw = pdf.get_string_width(tag) + 4
        pdf.cell(tw, 4, tag, fill=True)
        pdf.cell(2, 4, "")

    # Adjust card height to actual content
    actual_h = pdf.get_y() - card_y + 5
    pdf.set_fill_color(*color)
    pdf.rect(10, card_y, 3, actual_h, "F")

    pdf.set_y(pdf.get_y() + 8)

# --- PAGE 4: SEVERITY DISTRIBUTION ---
pdf.add_page()
pdf.section_title("4", "Severity Distribution & Risk Category Breakdown")
pdf.ln(2)

pdf.set_font("Helvetica", "", 10)
pdf.set_text_color(60, 60, 60)
pdf.multi_cell(0, 5, f"The {total_risks} total risks span multiple categories affecting the target deployment.")
pdf.ln(5)

# Severity table
sev_headers = ["Severity Level", "Count", "% of Total", "Definition"]
sev_col_w = [45, 25, 25, 95]

pdf.set_font("Helvetica", "B", 9)
pdf.set_fill_color(52, 73, 94)
pdf.set_text_color(255, 255, 255)
for j, h in enumerate(sev_headers):
    pdf.cell(sev_col_w[j], 8, h, border=1, fill=True, align="C")
pdf.ln()

sev_data = [
    ("HIGH (Critical)", high_count, (192, 57, 43), "High-confidence failure mode with direct outage potential"),
    ("MEDIUM (Warning)", medium_count, (230, 126, 34), "Elevated risk requiring near-term attention"),
    ("LOW (Info)", low_count, (41, 128, 185), "Low-severity observation or best-practice deviation"),
]

for label, count, tc, defn in sev_data:
    pct = f"{round(count/total_risks*100)}%" if total_risks > 0 else "0%"
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(*tc)
    pdf.set_fill_color(255, 255, 255)
    pdf.cell(sev_col_w[0], 8, label, border=1, fill=True)
    pdf.set_text_color(50, 50, 50)
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(sev_col_w[1], 8, str(count), border=1, align="C")
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(sev_col_w[2], 8, pct, border=1, align="C")
    pdf.cell(sev_col_w[3], 8, defn, border=1)
    pdf.ln()

# Total row
pdf.set_font("Helvetica", "B", 9)
pdf.set_fill_color(236, 240, 241)
pdf.set_text_color(44, 62, 80)
pdf.cell(sev_col_w[0], 8, "TOTAL", border=1, fill=True)
pdf.cell(sev_col_w[1], 8, str(total_risks), border=1, fill=True, align="C")
pdf.cell(sev_col_w[2], 8, "100%", border=1, fill=True, align="C")
pdf.cell(sev_col_w[3], 8, f"Across all services in scan scope", border=1, fill=True)
pdf.ln(10)

# Risk by category
pdf.set_font("Helvetica", "B", 13)
pdf.set_text_color(44, 62, 80)
pdf.cell(0, 8, "Risk Count by Category", ln=True)
pdf.ln(3)

cat_headers = ["Category", "Count", "Risks Included"]
cat_col_w = [45, 25, 120]

pdf.set_font("Helvetica", "B", 9)
pdf.set_fill_color(52, 73, 94)
pdf.set_text_color(255, 255, 255)
for j, h in enumerate(cat_headers):
    pdf.cell(cat_col_w[j], 8, h, border=1, fill=True, align="C")
pdf.ln()

avail_count = sum(1 for r in risks if "availability" in r.get("tags", []))
reliab_count = sum(1 for r in risks if "reliability" in r.get("tags", []))
security_count = sum(1 for r in risks if "security" in r.get("tags", []))

categories = [
    ("Availability", avail_count, (192, 57, 43), "Single-replica, missing probes, pod anti-affinity"),
    ("Reliability", reliab_count, (230, 126, 34), "Missing resource limits/requests, latest image tag"),
    ("Security", security_count, (41, 128, 185), "Missing network policy, lateral movement risk"),
]

for cat_name, cat_count, tc, desc in categories:
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(*tc)
    pdf.set_fill_color(255, 255, 255)
    pdf.cell(cat_col_w[0], 8, cat_name, border=1, fill=True)
    pdf.set_text_color(50, 50, 50)
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(cat_col_w[1], 8, str(cat_count), border=1, align="C")
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(cat_col_w[2], 8, desc, border=1)
    pdf.ln()

# --- PAGE 5: RECOMMENDATIONS ---
pdf.add_page()
pdf.section_title("5", "Recommendations & Next Steps")
pdf.ln(2)

pdf.set_font("Helvetica", "", 10)
pdf.set_text_color(60, 60, 60)
pdf.multi_cell(0, 5, f"Prioritised actions to reduce the pipeline risk score from {risk_score} to below the recommended gate threshold of 100 within the next two sprint cycles.")
pdf.ln(5)

rec_headers = ["Priority", "Service", "Action", "Experiment Type"]
rec_col_w = [20, 30, 80, 60]

pdf.set_font("Helvetica", "B", 9)
pdf.set_fill_color(52, 73, 94)
pdf.set_text_color(255, 255, 255)
for j, h in enumerate(rec_headers):
    pdf.cell(rec_col_w[j], 8, h, border=1, fill=True, align="C")
pdf.ln()

for risk in risks:
    sev = risk["severity"]
    tp = risk.get("metadata", {}).get("targetPrincipal", {})
    ident = tp.get("identification", {})
    target_name = ident.get("name", "N/A")

    if "resource-limits" in risk["name"]:
        action = "Add CPU/memory limits"
        experiment = "Memory Stress"
    elif "single-replica" in risk["name"]:
        action = "Increase replicas + add PDB"
        experiment = "Pod Delete"
    elif "resource-requests" in risk["name"]:
        action = "Add resource requests for QoS"
        experiment = "Pod Delete (pressure)"
    elif "missing-probes" in risk["name"]:
        action = "Add liveness/readiness probes"
        experiment = "Pod Delete + traffic"
    elif "network-policy" in risk["name"]:
        action = "Create NetworkPolicy"
        experiment = "Network Partition"
    elif "pod-anti-affinity" in risk["name"]:
        action = "Add podAntiAffinity"
        experiment = "Node Drain"
    elif "latest-image-tag" in risk["name"]:
        action = "Pin image to version/SHA"
        experiment = "Rolling Update"
    else:
        action = "Review and remediate"
        experiment = "General chaos"

    priority = "P1" if sev == "High" else "P2" if sev == "Medium" else "P3"
    pc = severity_colors.get(sev, (50, 50, 50))

    pdf.set_font("Helvetica", "B", 9)
    pdf.set_fill_color(*pc)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(rec_col_w[0], 8, priority, border=1, fill=True, align="C")

    pdf.set_text_color(44, 62, 80)
    pdf.set_fill_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(rec_col_w[1], 8, target_name, border=1)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(50, 50, 50)
    pdf.cell(rec_col_w[2], 8, action, border=1)
    pdf.cell(rec_col_w[3], 8, experiment, border=1)
    pdf.ln()

pdf.ln(8)

# Recommended Immediate Action box
pdf.set_fill_color(253, 236, 234)
pdf.set_draw_color(192, 57, 43)
box_y = pdf.get_y()
pdf.rect(10, box_y, 190, 22, "DF")
pdf.set_fill_color(192, 57, 43)
pdf.rect(10, box_y, 3, 22, "F")

pdf.set_xy(16, box_y + 3)
pdf.set_font("Helvetica", "B", 10)
pdf.set_text_color(192, 57, 43)
pdf.cell(0, 5, "Recommended Immediate Action:")
pdf.set_xy(16, box_y + 9)
pdf.set_font("Helvetica", "", 9)
pdf.set_text_color(60, 60, 60)
pdf.multi_cell(180, 4, f"Run a pod-delete chaos experiment against {', '.join(sorted(target_services))} -- the deployment is single-replica with no health probes and zero resilience test coverage. This will immediately confirm or disprove complete service outage on pod eviction.")

pdf.set_y(box_y + 27)

# Auto-parameterised box
pdf.set_fill_color(245, 247, 249)
pdf.set_draw_color(44, 62, 80)
box_y2 = pdf.get_y()
pdf.rect(10, box_y2, 190, 18, "DF")
pdf.set_fill_color(44, 62, 80)
pdf.rect(10, box_y2, 3, 18, "F")

pdf.set_xy(16, box_y2 + 3)
pdf.set_font("Helvetica", "B", 9)
pdf.set_text_color(44, 62, 80)
pdf.cell(0, 5, "Auto-parameterised experiment config:")
pdf.set_xy(16, box_y2 + 9)
pdf.set_font("Helvetica", "", 8)
pdf.set_text_color(60, 60, 60)
pdf.multi_cell(180, 4, f"target namespace = {namespace}, blast radius = 100%, steady-state hypothesis = HTTP 200 on health endpoint at p99 < 500ms, duration = 5 min, rollback on error rate > 2x baseline.")

# --- PAGE 6: TEST COVERAGE GAP ---
pdf.add_page()
pdf.section_title("6", "Test Coverage Gap Analysis")
pdf.ln(2)

pdf.set_font("Helvetica", "", 10)
pdf.set_text_color(60, 60, 60)
pdf.multi_cell(0, 5, "Zero coverage means a service's resilience posture is entirely unverified -- all passive risks remain unconfirmed and no steady-state baseline has been established.")
pdf.ln(5)

cov_headers = ["Service", "Chaos Tests", "Load Tests", "Coverage %", "Notes"]
cov_col_w = [35, 30, 30, 25, 70]

pdf.set_font("Helvetica", "B", 9)
pdf.set_fill_color(52, 73, 94)
pdf.set_text_color(255, 255, 255)
for j, h in enumerate(cov_headers):
    pdf.cell(cov_col_w[j], 8, h, border=1, fill=True, align="C")
pdf.ln()

for svc in sorted(target_services):
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(44, 62, 80)
    pdf.set_fill_color(255, 255, 255)
    pdf.cell(cov_col_w[0], 8, svc, border=1)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(50, 50, 50)
    pdf.cell(cov_col_w[1], 8, "None -- Gap", border=1, align="C")
    pdf.cell(cov_col_w[2], 8, "None -- Gap", border=1, align="C")
    pdf.set_text_color(192, 57, 43)
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(cov_col_w[3], 8, "0%", border=1, align="C")
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(50, 50, 50)
    pdf.cell(cov_col_w[4], 8, "Critical: no tests of any kind", border=1)
    pdf.ln()

# Summary row
pdf.set_font("Helvetica", "B", 9)
pdf.set_fill_color(192, 57, 43)
pdf.set_text_color(255, 255, 255)
pdf.cell(cov_col_w[0], 8, "SUMMARY", border=1, fill=True)
pdf.cell(cov_col_w[1], 8, f"0/{len(target_services)} covered", border=1, fill=True, align="C")
pdf.cell(cov_col_w[2], 8, f"0/{len(target_services)} covered", border=1, fill=True, align="C")
pdf.cell(cov_col_w[3], 8, "Avg 0%", border=1, fill=True, align="C")
pdf.cell(cov_col_w[4], 8, "Immediate action required", border=1, fill=True)
pdf.ln(10)

pdf.set_font("Helvetica", "I", 8)
pdf.set_text_color(130, 130, 130)
pdf.multi_cell(0, 4, f"Services with no tests of any kind: {', '.join(sorted(target_services))} -- {len(target_services)} of {len(target_services)} services.")

# --- PAGE 7: GLOSSARY ---
pdf.add_page()
pdf.section_title("", "Appendix -- About This Report & Glossary")
pdf.ln(2)

pdf.set_font("Helvetica", "", 10)
pdf.set_text_color(60, 60, 60)
pdf.multi_cell(0, 5,
    "This report was generated by the Harness Resilience Testing PRD-Report API (experimental). It is "
    "produced automatically at the end of each CD pipeline execution without requiring any code changes, "
    "instrumentation, or manual scan initiation. All findings are derived from static metadata analysis only "
    "-- no live traffic was affected and no faults were injected to produce this report.")
pdf.ln(3)
pdf.multi_cell(0, 5,
    "Risk taxonomy follows the classification defined in Harness Resilience Testing PRD Section 5A (v0.1, "
    "May 2026). Monetary estimates are illustrative and not contractual.")
pdf.ln(8)

glossary = [
    ("Term", "Definition"),
    ("RRS", "Resilience Risk Score -- composite: HIGH x 10 + MEDIUM x 4 + LOW x 1"),
    ("PDB", "PodDisruptionBudget -- K8s policy limiting simultaneous pod evictions"),
    ("HPA", "HorizontalPodAutoscaler -- auto-scales pod count based on load metrics"),
    ("MTTR", "Mean Time To Recovery -- average time to restore service after incident"),
    ("PRD-Report", "Passive Risk Detection Report -- API-driven risk scan anchored to CD pipeline"),
    ("HIGH", "High-confidence failure mode with direct outage potential"),
    ("MEDIUM", "Elevated risk requiring near-term attention"),
    ("LOW", "Low-severity observation or best-practice deviation"),
]

gl_col_w = [35, 155]
for i, (term, defn) in enumerate(glossary):
    if i == 0:
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_fill_color(52, 73, 94)
        pdf.set_text_color(255, 255, 255)
    else:
        pdf.set_fill_color(255, 255, 255) if i % 2 == 1 else pdf.set_fill_color(249, 249, 249)
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(192, 57, 43)
    pdf.cell(gl_col_w[0], 8, term, border=1, fill=True)
    if i == 0:
        pdf.set_text_color(255, 255, 255)
    else:
        pdf.set_text_color(50, 50, 50)
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(gl_col_w[1], 8, defn, border=1, fill=True)
    pdf.ln()

# Output
pdf.output(OUTPUT_PDF)
print(f"PDF generated successfully: {OUTPUT_PDF}")
print(f"File size: {os.path.getsize(OUTPUT_PDF)} bytes")

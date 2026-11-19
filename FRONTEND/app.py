
import streamlit as st
import requests
import pandas as pd
import plotly.express as px

from io import BytesIO
from datetime import datetime
from xml.sax.saxutils import escape

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm


# --------------------------------
# CONFIGURATION
# --------------------------------

API_URL = "http://127.0.0.1:8000"

st.set_page_config(
    page_title="ThreatGuard AI",
    page_icon="🛡️",
    layout="wide"
)


# --------------------------------
# CUSTOM CSS
# --------------------------------

st.markdown("""
<style>
.stApp {
    background-color: #F5F7FB;
}

[data-testid="stSidebar"] {
    background-color: #17233D;
}

[data-testid="stSidebar"] * {
    color: white;
}

.main-title {
    font-size: 34px;
    font-weight: bold;
    color: #17233D;
}

.subtitle {
    font-size: 16px;
    color: #68758A;
}

div[data-testid="stMetric"] {
    background-color: white;
    padding: 18px;
    border-radius: 12px;
    border: 1px solid #E5E8EF;
}

.auth-box {
    background-color: white;
    padding: 25px;
    border-radius: 12px;
}
</style>
""", unsafe_allow_html=True)


# --------------------------------
# SESSION STATE
# --------------------------------

defaults = {
    "messages": [],
    "access_token": None,
    "user": None,
    "auth_mode": "Login"
}

for key, value in defaults.items():
    if key not in st.session_state:
        st.session_state[key] = value


# --------------------------------
# API AUTHENTICATION HEADERS
# --------------------------------

def get_headers():

    token = st.session_state.access_token

    return {
        "Authorization": f"Bearer {token}"
    }


# --------------------------------
# LOGIN AND REGISTRATION FUNCTIONS
# --------------------------------

def login_user(email, password):

    try:
        response = requests.post(
            f"{API_URL}/login",
            json={
                "email": email,
                "password": password
            },
            timeout=15
        )

        if response.status_code == 200:

            data = response.json()

            st.session_state.access_token = data["access_token"]
            st.session_state.user = data["user"]
            st.session_state.messages = []

            return True, data.get("message", "Login successful!")

        try:
            error = response.json().get("detail", "Login failed.")
        except ValueError:
            error = "Login failed."

        return False, error

    except requests.RequestException:
        return False, "Cannot connect to backend. Please start FastAPI."


def register_user(name, email, password):

    try:
        response = requests.post(
            f"{API_URL}/register",
            json={
                "name": name,
                "email": email,
                "password": password
            },
            timeout=15
        )

        if response.status_code == 200:
            return True, response.json().get(
                "message",
                "Account created successfully!"
            )

        try:
            error = response.json().get("detail", "Registration failed.")
        except ValueError:
            error = "Registration failed."

        return False, error

    except requests.RequestException:
        return False, "Cannot connect to backend. Please start FastAPI."


# --------------------------------
# API FUNCTIONS
# --------------------------------

def get_threat_data():

    try:
        response = requests.get(
            f"{API_URL}/threats?platform=Windows",
            headers=get_headers(),
            timeout=10
        )

        response.raise_for_status()

        return response.json().get("threats", [])

    except requests.RequestException:
        return None


def get_chat_history():

    try:
        response = requests.get(
            f"{API_URL}/history",
            headers=get_headers(),
            timeout=10
        )

        response.raise_for_status()

        return response.json().get("history", [])

    except requests.RequestException:
        return []


# --------------------------------
# PDF REPORT GENERATION
# --------------------------------

def generate_pdf_report(threats):

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=20,
        leading=25,
        textColor=colors.HexColor("#17233D"),
        spaceAfter=12
    )

    heading_style = ParagraphStyle(
        "ReportHeading",
        parent=styles["Heading2"],
        textColor=colors.HexColor("#17233D"),
        spaceBefore=12,
        spaceAfter=8
    )

    body_style = styles["BodyText"]

    content = []

    content.append(
        Paragraph("ThreatGuard AI - Security Report", title_style)
    )

    content.append(
        Paragraph(
            "Educational Cybersecurity Threat Summary",
            styles["Heading2"]
        )
    )

    content.append(Spacer(1, 10))

    content.append(
        Paragraph(
            "Generated on: " + datetime.now().strftime("%d-%m-%Y %H:%M"),
            body_style
        )
    )

    content.append(Spacer(1, 15))

    # Threat counts

    total = len(threats)

    statuses = ["Active", "Anticipated", "Evolving", "Resolved"]
    severities = ["High", "Medium", "Low"]

    summary_data = [
        ["Metric", "Count"],
        ["Total Threats", str(total)]
    ]

    for status in statuses:
        count = sum(
            1 for t in threats
            if t.get("status", "").lower() == status.lower()
        )
        summary_data.append([status, str(count)])

    for severity in severities:
        count = sum(
            1 for t in threats
            if t.get("severity", "").lower() == severity.lower()
        )
        summary_data.append([severity + " Severity", str(count)])

    content.append(
        Paragraph("Threat Summary", heading_style)
    )

    summary_table = Table(
        summary_data,
        colWidths=[85 * mm, 65 * mm]
    )

    summary_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17233D")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("PADDING", (0, 0), (-1, -1), 8),
            ("BACKGROUND", (0, 1), (-1, -1), colors.whitesmoke)
        ])
    )

    content.append(summary_table)
    content.append(Spacer(1, 20))

    # Individual threat details

    content.append(
        Paragraph("Threat Details", heading_style)
    )

    for index, threat in enumerate(threats, start=1):

        content.append(Spacer(1, 10))

        title = escape(str(threat.get("title", "Unknown Threat")))
        platform = escape(str(threat.get("platform", "Unknown")))
        status = escape(str(threat.get("status", "Unknown")))
        severity = escape(str(threat.get("severity", "Unknown")))
        description = escape(
            str(threat.get("description", "Not available"))
        )

        content.append(
            Paragraph(f"{index}. {title}", styles["Heading3"])
        )

        content.append(
            Paragraph(f"<b>Platform:</b> {platform}", body_style)
        )

        content.append(
            Paragraph(f"<b>Status:</b> {status}", body_style)
        )

        content.append(
            Paragraph(f"<b>Severity:</b> {severity}", body_style)
        )

        content.append(
            Paragraph(f"<b>Description:</b> {description}", body_style)
        )

        content.append(Spacer(1, 5))

        content.append(
            Paragraph("<b>Mitigation Recommendations:</b>", body_style)
        )

        mitigation = threat.get("mitigation", [])

        if mitigation:
            for step in mitigation:
                content.append(
                    Paragraph(
                        f"&#8226; {escape(str(step))}",
                        body_style
                    )
                )
        else:
            content.append(
                Paragraph(
                    "No mitigation recommendations available.",
                    body_style
                )
            )

        content.append(Spacer(1, 12))

    content.append(Spacer(1, 15))

    content.append(
        Paragraph(
            "<b>Disclaimer:</b> This report uses educational sample data. "
            "It does not represent live threat scanning or verified "
            "security incidents. Mitigation steps are recommendations "
            "and are not automatically executed.",
            styles["Italic"]
        )
    )

    document.build(content)

    buffer.seek(0)

    return buffer.getvalue()


# ==========================================
# LOGIN / REGISTRATION SCREEN
# ==========================================

if not st.session_state.access_token:

    st.markdown("<br><br>", unsafe_allow_html=True)

    left, center, right = st.columns([1, 1.4, 1])

    with center:

        st.markdown(
            '<div class="main-title">🛡️ ThreatGuard AI</div>',
            unsafe_allow_html=True
        )

        st.markdown(
            '<div class="subtitle">'
            'AI-Powered Cybersecurity Threat Detection and Mitigation'
            '</div>',
            unsafe_allow_html=True
        )

        st.write("")

        login_tab, register_tab = st.tabs(
            ["🔐 Login", "📝 Register"]
        )

        # LOGIN FORM

        with login_tab:

            st.subheader("Welcome Back!")

            st.write("Log in to access your security dashboard.")

            with st.form("login_form"):

                email = st.text_input(
                    "Email Address",
                    placeholder="Enter your email"
                )

                password = st.text_input(
                    "Password",
                    type="password",
                    placeholder="Enter your password"
                )

                login_button = st.form_submit_button(
                    "Login",
                    use_container_width=True
                )

            if login_button:

                if not email.strip() or not password:
                    st.error("Please enter your email and password.")

                else:
                    success, message = login_user(email, password)

                    if success:
                        st.success(message)
                        st.rerun()
                    else:
                        st.error(message)

        # REGISTRATION FORM

        with register_tab:

            st.subheader("Create Your Account")

            st.write("Register to start using ThreatGuard AI.")

            with st.form("register_form"):

                name = st.text_input(
                    "Full Name",
                    placeholder="Enter your name"
                )

                new_email = st.text_input(
                    "Email Address",
                    placeholder="Enter your email"
                )

                new_password = st.text_input(
                    "Create Password",
                    type="password",
                    placeholder="Minimum 8 characters"
                )

                confirm_password = st.text_input(
                    "Confirm Password",
                    type="password",
                    placeholder="Re-enter your password"
                )

                register_button = st.form_submit_button(
                    "Create Account",
                    use_container_width=True
                )

            if register_button:

                if not name.strip() or not new_email.strip():
                    st.error("Please fill in all the fields.")

                elif len(new_password) < 8:
                    st.error("Password must contain at least 8 characters.")

                elif new_password != confirm_password:
                    st.error("Passwords do not match.")

                else:

                    success, message = register_user(
                        name,
                        new_email,
                        new_password
                    )

                    if success:
                        st.success(
                            "Account created successfully! "
                            "Please go to the Login tab."
                        )
                    else:
                        st.error(message)

        st.divider()

        st.caption(
            "ThreatGuard AI | Educational Cybersecurity Demonstration"
        )

    st.stop()


# ==========================================
# MAIN DASHBOARD - LOGGED-IN USERS ONLY
# ==========================================

user = st.session_state.user


# --------------------------------
# SIDEBAR
# --------------------------------

with st.sidebar:

    st.markdown("# 🛡️ ThreatGuard AI")

    st.caption("AI-Powered Cybersecurity Assistant")

    st.divider()

    st.markdown("### 👤 My Account")

    st.write(user.get("name", "User"))

    st.caption(user.get("email", ""))

    if st.button(
        "🚪 Logout",
        use_container_width=True
    ):

        try:
            requests.post(
                f"{API_URL}/logout",
                headers=get_headers(),
                timeout=10
            )
        except requests.RequestException:
            pass

        st.session_state.access_token = None
        st.session_state.user = None
        st.session_state.messages = []

        st.rerun()

    st.divider()

    if st.button(
        "➕ New Chat",
        use_container_width=True
    ):

        st.session_state.messages = []
        st.rerun()

    st.markdown("### 💬 Recent Conversations")

    saved_history = get_chat_history()

    if saved_history:

        for item in saved_history[:5]:

            previous_message = item.get(
                "user_message",
                "Previous conversation"
            )

            st.caption(
                "• " + str(previous_message)[:55]
            )

    else:

        st.caption("No saved conversations yet.")

    st.divider()

    if st.button(
        "🗑️ Clear Current Chat",
        use_container_width=True
    ):

        st.session_state.messages = []
        st.rerun()

    st.divider()

    st.caption("ThreatGuard AI")
    st.caption("Cybersecurity Threat Intelligence System")


# --------------------------------
# MAIN HEADER
# --------------------------------

st.markdown(
    '<div class="main-title">🛡️ ThreatGuard AI Dashboard</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">'
    'AI-powered cybersecurity threat detection and mitigation recommendations'
    '</div>',
    unsafe_allow_html=True
)

st.write("")

st.success(
    f"Welcome, {user.get('name', 'User')}! You are logged in."
)


# --------------------------------
# FETCH THREAT DATA
# --------------------------------

threats = get_threat_data()

if threats is None:

    st.error(
        "Unable to connect to the backend or your login session has expired. "
        "Please log out and log in again."
    )

    st.stop()


# --------------------------------
# DASHBOARD METRICS
# --------------------------------

st.markdown("## 📊 Security Dashboard")

active_count = sum(
    1 for t in threats
    if t.get("status", "").lower() == "active"
)

anticipated_count = sum(
    1 for t in threats
    if t.get("status", "").lower() == "anticipated"
)

evolving_count = sum(
    1 for t in threats
    if t.get("status", "").lower() == "evolving"
)

resolved_count = sum(
    1 for t in threats
    if t.get("status", "").lower() == "resolved"
)

total_count = len(threats)

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("Total Threats", total_count)

with col2:
    st.metric("Active", active_count)

with col3:
    st.metric("Anticipated", anticipated_count)

with col4:
    st.metric("Resolved", resolved_count)


# --------------------------------
# THREAT SEVERITY ANALYSIS
# --------------------------------

st.markdown("### 📊 Threat Severity Analysis")

high = sum(
    1 for t in threats
    if t.get("severity", "").lower() == "high"
)

medium = sum(
    1 for t in threats
    if t.get("severity", "").lower() == "medium"
)

low = sum(
    1 for t in threats
    if t.get("severity", "").lower() == "low"
)

severity_df = pd.DataFrame({
    "Severity": ["High", "Medium", "Low"],
    "Number of Threats": [high, medium, low]
})

fig = px.bar(
    severity_df,
    x="Severity",
    y="Number of Threats",
    color="Severity",
    text="Number of Threats",
    color_discrete_map={
        "High": "#DC5555",
        "Medium": "#D9A441",
        "Low": "#319B70"
    },
    title="Threats by Severity Level"
)

fig.update_traces(
    textposition="inside",
    textfont_size=16,
    insidetextanchor="middle"
)

fig.update_layout(
    xaxis_title="Severity Level",
    yaxis_title="Number of Threats",
    yaxis=dict(
        dtick=1,
        range=[0, max(3, high, medium, low)]
    ),
    showlegend=False,
    plot_bgcolor="white",
    paper_bgcolor="white",
    bargap=0.4
)

st.plotly_chart(
    fig,
    use_container_width=True
)

st.caption("Severity distribution based on database records.")


# --------------------------------
# DETECTED THREATS WITH SEARCH/FILTER
# --------------------------------

st.divider()

st.markdown("### 🔍 Detected Threats")

search_query = st.text_input(
    "Search threats",
    placeholder="Search by threat name, description or keyword..."
)

status_filter = st.selectbox(
    "Filter threats by status:",
    [
        "All Threats",
        "Active",
        "Anticipated",
        "Evolving",
        "Resolved"
    ]
)

filtered_threats = threats

if status_filter != "All Threats":

    filtered_threats = [
        t for t in filtered_threats
        if t.get("status", "").lower() == status_filter.lower()
    ]

if search_query.strip():

    query = search_query.strip().lower()

    filtered_threats = [
        t for t in filtered_threats
        if query in str(t.get("title", "")).lower()
        or query in str(t.get("description", "")).lower()
        or query in str(t.get("platform", "")).lower()
        or query in str(t.get("severity", "")).lower()
        or query in str(t.get("status", "")).lower()
    ]

st.caption(
    f"Showing {len(filtered_threats)} of {len(threats)} threats"
)

if filtered_threats:

    for threat in filtered_threats:

        title = threat.get("title", "Unknown Threat")
        status = threat.get("status", "Unknown")
        severity = threat.get("severity", "Unknown")

        with st.expander(
            f"⚠️ {title} | {status} | {severity}"
        ):

            st.write("**Platform:**", threat.get("platform", "Unknown"))
            st.write("**Status:**", status)
            st.write("**Severity:**", severity)

            st.write(
                "**Description:**",
                threat.get("description", "No description available.")
            )

            st.markdown("**Mitigation Recommendations:**")

            mitigation = threat.get("mitigation", [])

            if mitigation:
                for step in mitigation:
                    st.write("• " + step)
            else:
                st.write("No mitigation steps available.")

            if threat.get("sample_data"):
                st.caption("Educational demonstration dataset.")

else:

    st.warning("No matching threats found. Try another search.")


# --------------------------------
# DOWNLOAD SECURITY REPORT
# --------------------------------

st.divider()

st.markdown("### 📥 Download Security Report")

st.write(
    "Generate a PDF report containing threat summaries, "
    "severity levels, descriptions and mitigation recommendations."
)

try:

    pdf_data = generate_pdf_report(threats)

    st.download_button(
        label="📄 Download Threat Report (PDF)",
        data=pdf_data,
        file_name="ThreatGuard_AI_Security_Report.pdf",
        mime="application/pdf",
        use_container_width=True
    )

except Exception as e:

    st.error("Unable to generate the PDF report.")
    st.caption(str(e))


# --------------------------------
# CHATBOT SECTION
# --------------------------------

st.divider()

st.markdown("## 🤖 ThreatGuard AI Chat Assistant")

st.write(
    "Ask questions about Windows security threats, "
    "their severity, status and mitigation recommendations."
)


# --------------------------------
# WELCOME MESSAGE
# --------------------------------

if not st.session_state.messages:

    st.info(
        "Hello! I am ThreatGuard AI. "
        "How can I help you with cybersecurity today?"
    )

    st.markdown("### 💡 Try asking:")

    col1, col2 = st.columns(2)

    with col1:
        st.write("• What are the active threats in Windows?")
        st.write("• How can I prevent malware attacks?")

    with col2:
        st.write("• Show me the evolving threats.")
        st.write("• How can I protect myself from phishing?")


# --------------------------------
# DISPLAY CHAT MESSAGES
# --------------------------------

for message in st.session_state.messages:

    with st.chat_message(message["role"]):
        st.markdown(message["content"])


# --------------------------------
# CHAT INPUT
# --------------------------------

user_input = st.chat_input(
    "Ask ThreatGuard AI about cybersecurity..."
)

if user_input:

    st.session_state.messages.append({
        "role": "user",
        "content": user_input
    })

    with st.chat_message("user"):
        st.markdown(user_input)

    with st.chat_message("assistant"):

        with st.spinner("ThreatGuard AI is analysing..."):

            try:

                response = requests.post(
                    f"{API_URL}/chat",
                    json={"message": user_input},
                    headers=get_headers(),
                    timeout=120
                )

                response.raise_for_status()

                answer = response.json().get(
                    "response",
                    "No response received from the AI."
                )

                st.markdown(answer)

                st.session_state.messages.append({
                    "role": "assistant",
                    "content": answer
                })

            except requests.HTTPError as e:

                if response.status_code == 401:
                    answer = (
                        "Your login session has expired. "
                        "Please log out and log in again."
                    )
                else:
                    answer = "The chatbot request failed. Please try again."

                st.error(answer)
                st.caption(str(e))

            except requests.RequestException as e:

                answer = (
                    "Unable to connect to the chatbot backend. "
                    "Please check whether FastAPI is running."
                )

                st.error(answer)
                st.caption(str(e))


# --------------------------------
# FOOTER
# --------------------------------

st.divider()

st.caption(
    "ThreatGuard AI | Educational Cybersecurity Demonstration"
)

st.caption(
    "Threat records are sample data. This application provides "
    "recommendations and does not perform live security scans "
    "or automatically execute mitigation actions."
)










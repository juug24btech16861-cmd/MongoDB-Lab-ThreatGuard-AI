import os
import streamlit as st
import requests

# ==========================================
# THREATGUARD AI - FRONTEND CONFIGURATION
# ==========================================

API_URL = os.getenv("API_URL", "http://127.0.0.1:8000")

st.set_page_config(
    page_title="ThreatGuard AI",
    page_icon="🛡️",
    layout="wide"
)

# ==========================================
# SESSION INITIALIZATION
# ==========================================

if "token" not in st.session_state:
    st.session_state.token = None

if "user" not in st.session_state:
    st.session_state.user = None

if "messages" not in st.session_state:
    st.session_state.messages = []


# ==========================================
# API HELPERS
# ==========================================

def get_headers():
    if st.session_state.token:
        return {
            "Authorization": f"Bearer {st.session_state.token}"
        }
    return {}


def api_error(response):
    try:
        return response.json().get("detail", "Request failed.")
    except ValueError:
        return "An unexpected server error occurred."


# ==========================================
# APPLICATION TITLE
# ==========================================

st.title("🛡️ ThreatGuard AI")
st.caption("AI-Based Cybersecurity Threat Intelligence Assistant")

st.divider()


# ==========================================
# LOGIN AND REGISTRATION
# ==========================================

if not st.session_state.token:

    login_tab, register_tab = st.tabs(
        ["Login", "Create Account"]
    )

    # --------------------------------------
    # LOGIN
    # --------------------------------------

    with login_tab:

        st.subheader("Login to ThreatGuard AI")

        with st.form("login_form"):

            email = st.text_input("Email Address")
            password = st.text_input(
                "Password",
                type="password"
            )

            login_button = st.form_submit_button(
                "Login",
                use_container_width=True
            )

        if login_button:

            try:

                response = requests.post(
                    f"{API_URL}/login",
                    json={
                        "email": email,
                        "password": password
                    },
                    timeout=30
                )

                if response.status_code == 200:

                    data = response.json()

                    st.session_state.token = data["access_token"]
                    st.session_state.user = data["user"]
                    st.session_state.messages = []

                    st.success("Login successful!")
                    st.rerun()

                else:

                    st.error(api_error(response))

            except requests.RequestException:

                st.error(
                    "Cannot connect to the backend. "
                    "Please start FastAPI first."
                )

    # --------------------------------------
    # REGISTRATION
    # --------------------------------------

    with register_tab:

        st.subheader("Create a New Account")

        with st.form("register_form"):

            name = st.text_input("Full Name")
            new_email = st.text_input("Email Address")
            new_password = st.text_input(
                "Password",
                type="password"
            )

            register_button = st.form_submit_button(
                "Register",
                use_container_width=True
            )

        if register_button:

            try:

                response = requests.post(
                    f"{API_URL}/register",
                    json={
                        "name": name,
                        "email": new_email,
                        "password": new_password
                    },
                    timeout=30
                )

                if response.status_code == 200:

                    st.success(
                        "Account created successfully! "
                        "Please log in."
                    )

                else:

                    st.error(api_error(response))

            except requests.RequestException:

                st.error(
                    "Cannot connect to the backend. "
                    "Please check FastAPI."
                )


# ==========================================
# MAIN DASHBOARD AFTER LOGIN
# ==========================================

else:

    user = st.session_state.user

    # --------------------------------------
    # SIDEBAR
    # --------------------------------------

    st.sidebar.title("🛡️ ThreatGuard AI")

    st.sidebar.success(
        f"Logged in as {user.get('name', 'User')}"
    )

    st.sidebar.divider()

    platform = st.sidebar.selectbox(
        "Select Platform",
        [
            "Windows",
            "Linux",
            "MacOS",
            "Android",
            "iOS"
        ]
    )

    status_filter = st.sidebar.selectbox(
        "Threat Status",
        [
            "All",
            "Anticipated",
            "Active",
            "Evolving",
            "Resolved"
        ]
    )

    if st.sidebar.button(
        "Logout",
        use_container_width=True
    ):

        try:
            requests.post(
                f"{API_URL}/logout",
                headers=get_headers(),
                timeout=15
            )
        except requests.RequestException:
            pass

        st.session_state.token = None
        st.session_state.user = None
        st.session_state.messages = []

        st.rerun()

    # --------------------------------------
    # DASHBOARD TABS
    # --------------------------------------

    dashboard_tab, chatbot_tab = st.tabs(
        ["Threat Dashboard", "AI Chatbot"]
    )

    # ======================================
    # THREAT DASHBOARD
    # ======================================

    with dashboard_tab:

        st.header("Threat Intelligence Dashboard")

        st.write(
            f"Viewing threat information for **{platform}**."
        )

        params = {}

        if status_filter != "All":
            params["status"] = status_filter

        try:

            response = requests.get(
                f"{API_URL}/threats",
                params={
                    "platform": platform,
                    **params
                },
                headers=get_headers(),
                timeout=30
            )

            if response.status_code == 200:

                threats = response.json().get("threats", [])

                if threats:

                    st.success(
                        f"{len(threats)} threat record(s) found."
                    )

                    for threat in threats:

                        with st.expander(
                            threat.get("title", "Unknown Threat")
                        ):

                            st.write(
                                "**Platform:**",
                                threat.get("platform", "Unknown")
                            )

                            st.write(
                                "**Status:**",
                                threat.get("status", "Unknown")
                            )

                            st.write(
                                "**Severity:**",
                                threat.get("severity", "Unknown")
                            )

                            st.write(
                                "**Description:**",
                                threat.get("description", "Not available")
                            )

                            st.write("**Mitigation Recommendations:**")

                            mitigation = threat.get("mitigation", [])

                            if mitigation:

                                for step in mitigation:
                                    st.write(f"- {step}")

                            else:
                                st.write("No recommendations available.")

                else:

                    st.info(
                        "No threat records found for the selected platform."
                    )

            else:

                st.error(api_error(response))

        except requests.RequestException:

            st.error(
                "Unable to retrieve threats. "
                "Check whether the backend is running."
            )

        st.caption(
            "Threat records are educational database records, "
            "not results of live security scans."
        )

    # ======================================
    # AI CHATBOT
    # ======================================

    with chatbot_tab:

        st.header("💬 ThreatGuard AI Chatbot")

        st.write(
            "Ask questions about cybersecurity threats, "
            "vulnerabilities and mitigation recommendations."
        )

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

        # DISPLAY CHAT HISTORY

        for message in st.session_state.messages:

            with st.chat_message(message["role"]):
                st.markdown(message["content"])

        # CHAT INPUT

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

                with st.spinner(
                    "ThreatGuard AI is analysing..."
                ):

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

                    except requests.HTTPError:

                        if response.status_code == 401:

                            st.error(
                                "Your login session has expired. "
                                "Please log in again."
                            )

                        else:

                            st.error(api_error(response))

                    except requests.RequestException:

                        st.error(
                            "Unable to connect to the chatbot backend. "
                            "Please check FastAPI."
                        )


# ==========================================
# FOOTER
# ==========================================

st.divider()

st.caption(
    "ThreatGuard AI | Educational Cybersecurity Demonstration"
)

st.caption(
    "Threat records are sample data. This application provides "
    "recommendations and does not perform live security scans "
    "or automatically execute mitigation actions."
)











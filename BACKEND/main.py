from BACKEND.database import initialize_database
from fastapi import (
    FastAPI,
    HTTPException,
    Depends
)

from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from pydantic import BaseModel, Field

from datetime import datetime, timezone, timedelta

import secrets

from BACKEND.llm import generate_answer

from BACKEND.database import (
    save_chat,
    get_chat_history,
    get_threats,
    search_threats,
    register_user,
    authenticate_user
)


# -----------------------------------------
# FASTAPI APPLICATION
# -----------------------------------------

app = FastAPI(title="ThreatGuard AI")
@app.on_event("startup")
def startup_event():
    initialize_database()

security = HTTPBearer()

# Demo session storage.
# Sessions are cleared when the backend restarts.
active_sessions = {}


# -----------------------------------------
# REQUEST MODELS
# -----------------------------------------

class RegisterRequest(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    email: str = Field(min_length=5, max_length=150)
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: str
    password: str


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=4000)


# -----------------------------------------
# AUTHENTICATION HELPER
# -----------------------------------------

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):

    token = credentials.credentials

    session = active_sessions.get(token)

    if not session:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired login session."
        )

    if datetime.now(timezone.utc) >= session["expires_at"]:

        active_sessions.pop(token, None)

        raise HTTPException(
            status_code=401,
            detail="Your login session has expired. Please log in again."
        )

    return session["user"]


# -----------------------------------------
# HOME ENDPOINT
# -----------------------------------------

@app.get("/")
def home():

    return {
        "message": "ThreatGuard AI is running!"
    }


# -----------------------------------------
# USER REGISTRATION
# -----------------------------------------

@app.post("/register")
def create_account(request: RegisterRequest):

    name = request.name.strip()
    email = request.email.strip().lower()

    if len(name) < 2:

        raise HTTPException(
            status_code=400,
            detail="Please enter a valid name."
        )

    if "@" not in email or "." not in email.split("@")[-1]:

        raise HTTPException(
            status_code=400,
            detail="Please enter a valid email address."
        )

    if len(request.password) < 8:

        raise HTTPException(
            status_code=400,
            detail="Password must contain at least 8 characters."
        )

    user = register_user(
        name,
        email,
        request.password
    )

    if not user:

        raise HTTPException(
            status_code=409,
            detail="This email is already registered or the details are invalid."
        )

    return {
        "message": "Account created successfully!",
        "user": user
    }


# -----------------------------------------
# USER LOGIN
# -----------------------------------------

@app.post("/login")
def login(request: LoginRequest):

    email = request.email.strip().lower()

    user = authenticate_user(
        email,
        request.password
    )

    if not user:

        raise HTTPException(
            status_code=401,
            detail="Incorrect email or password."
        )

    # Create a random login token
    token = secrets.token_urlsafe(32)

    # Session expires after 8 hours
    expires_at = datetime.now(timezone.utc) + timedelta(hours=8)

    active_sessions[token] = {
        "user": user,
        "expires_at": expires_at
    }

    return {
        "message": "Login successful!",
        "access_token": token,
        "token_type": "bearer",
        "user": user
    }


# -----------------------------------------
# GET LOGGED-IN USER
# -----------------------------------------

@app.get("/me")
def get_my_account(
    current_user: dict = Depends(get_current_user)
):

    return {
        "user": current_user
    }


# -----------------------------------------
# LOGOUT
# -----------------------------------------

@app.post("/logout")
def logout(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    current_user: dict = Depends(get_current_user)
):

    token = credentials.credentials

    active_sessions.pop(token, None)

    return {
        "message": "Logged out successfully!"
    }


# -----------------------------------------
# GET THREATS
# -----------------------------------------

@app.get("/threats")
def threats(
    platform: str = "Windows",
    status: str = None,
    current_user: dict = Depends(get_current_user)
):

    return {
        "threats": get_threats(platform, status)
    }


# -----------------------------------------
# GET USER CHAT HISTORY
# -----------------------------------------

@app.get("/history")
def history(
    current_user: dict = Depends(get_current_user)
):

    return {
        "history": get_chat_history(current_user["id"])
    }


# -----------------------------------------
# FORMAT THREAT INFORMATION
# -----------------------------------------

def format_threats(threat_list):

    if not threat_list:

        return "No threats found for this status in the database."

    result = []

    for index, threat in enumerate(threat_list, start=1):

        result.append(
            f"{index}. {threat.get('title', 'Unknown Threat')}\n"
            f"   Platform: {threat.get('platform', 'Unknown')}\n"
            f"   Status: {threat.get('status', 'Unknown')}\n"
            f"   Severity: {threat.get('severity', 'Unknown')}\n"
            f"   Description: {threat.get('description', 'Not available')}\n"
            f"   Mitigation recommendations:"
        )

        mitigation = threat.get("mitigation", [])

        if mitigation:

            for step in mitigation:
                result.append(f"   - {step}")

        else:

            result.append(
                "   - No mitigation recommendations available."
            )

    return "\n".join(result)


# -----------------------------------------
# CHAT ENDPOINT
# -----------------------------------------

@app.post("/chat")
def chat(
    request: ChatRequest,
    current_user: dict = Depends(get_current_user)
):

    message = request.message.strip()
    message_lower = message.lower()

    if not message:

        raise HTTPException(
            status_code=400,
            detail="Please enter a message."
        )

    # Get actual Windows threat records
    all_threats = get_threats("Windows")

    # -------------------------------------
    # HANDLE CONFIRMATION SAFELY
    # -------------------------------------

    if message_lower in [
        "confirm",
        "yes",
        "proceed",
        "go ahead"
    ]:

        response = (
            "ThreatGuard AI provides mitigation recommendations only. "
            "It does not execute security actions on your computer. "
            "Please follow the recommended steps manually."
        )

        save_chat(
            current_user["id"],
            message,
            response
        )

        return {
            "response": response
        }

    # -------------------------------------
    # HANDLE STATUS-BASED QUESTIONS
    # -------------------------------------

    statuses = {
        "active": "Active",
        "anticipated": "Anticipated",
        "evolving": "Evolving",
        "resolved": "Resolved"
    }

    requested_statuses = [
        status
        for keyword, status in statuses.items()
        if keyword in message_lower
    ]

    if requested_statuses:

        matching_threats = [
            threat for threat in all_threats
            if threat.get("status", "").lower()
            in [
                status.lower()
                for status in requested_statuses
            ]
        ]

        response_parts = []

        for status in requested_statuses:

            status_threats = [
                threat for threat in matching_threats
                if threat.get("status", "").lower()
                == status.lower()
            ]

            response_parts.append(
                f"{status} threats: {len(status_threats)}"
            )

            if status_threats:

                response_parts.append(
                    format_threats(status_threats)
                )

            else:

                response_parts.append(
                    f"No {status.lower()} threats are currently listed."
                )

        response = (
            "Based on the Windows threat records in the database:\n\n"
            + "\n\n".join(response_parts)
            + "\n\nThese are database records, not live scans of your computer. "
            "The mitigation steps are recommendations and are not "
            "automatically executed."
        )

        save_chat(
            current_user["id"],
            message,
            response
        )

        return {
            "response": response
        }

    # -------------------------------------
    # HANDLE GENERAL CYBERSECURITY QUESTIONS
    # -------------------------------------

    relevant_threats = search_threats(message)

    if not relevant_threats:
        relevant_threats = all_threats

    threat_context = format_threats(relevant_threats)

    messages = [
        {
            "role": "system",
            "content": (
                "You are ThreatGuard AI, a cybersecurity assistant. "
                "Answer using only the supplied database information "
                "when discussing stored threats. "
                "Never invent threat records, counts, statuses or severity. "
                "Do not change a threat's database status. "
                "Clearly explain threat descriptions and mitigation "
                "recommendations. "
                "The database may contain educational sample records. "
                "Never describe them as live or verified threats. "
                "You cannot scan the user's computer, quarantine files, "
                "install updates or execute mitigation actions. "
                "Never claim that you have performed these actions. "
                "Give safe, practical recommendations instead.\n\n"
                f"Threat database information:\n{threat_context}"
            )
        },
        {
            "role": "user",
            "content": message
        }
    ]

    response = generate_answer(messages)

    save_chat(
        current_user["id"],
        message,
        response
    )

    return {
        "response": response
    }







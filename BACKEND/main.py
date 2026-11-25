
import os
import requests
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from pymongo import MongoClient
from pymongo.errors import PyMongoError
from bson import ObjectId
from jose import jwt, JWTError
import bcrypt


# ============================================================
# CONFIGURATION
# ============================================================

APP_NAME = "ThreatGuard AI"

MONGO_URI = os.getenv(
    "MONGO_URI",
    "mongodb://localhost:27017/"
)

DATABASE_NAME = os.getenv(
    "DATABASE_NAME",
    "threatguard"
)

OLLAMA_URL = os.getenv(
    "OLLAMA_URL",
    "http://127.0.0.1:11434"
)

MODEL = os.getenv(
    "OLLAMA_MODEL",
    "qwen2.5:7b"
)

JWT_SECRET = os.getenv(
    "JWT_SECRET",
    "CHANGE_THIS_TO_A_LONG_RANDOM_SECRET"
)

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440


# ============================================================
# SYSTEM PROMPT
# ============================================================

SYSTEM_PROMPT = """
You are ThreatGuard AI, an intelligent, helpful, accurate,
general-purpose AI assistant with strong cybersecurity knowledge.

IDENTITY:
- Name: ThreatGuard AI
- AI Model: Qwen 2.5:7b
- AI Engine: Ollama
- Backend Framework: FastAPI
- Database: MongoDB
- Frontend: HTML, CSS and JavaScript
- Development Environment: Visual Studio Code

PROJECT ARCHITECTURE:
- Frontend runs using VS Code Live Server, normally on port 5500.
- FastAPI backend runs on port 8001.
- MongoDB stores user accounts, chat history and threat records.
- Ollama runs the Qwen 2.5:7b language model.
- Visual Studio Code is used to develop and edit the project.

IMPORTANT CONNECTION INFORMATION:

1. VISUAL STUDIO CODE:
ThreatGuard AI was developed using Visual Studio Code.
VS Code is a development environment, not a live runtime service.
Never falsely claim that VS Code has a live backend connection.

If asked whether the project is connected to VS Code:
Answer that it was developed using VS Code, but VS Code is
not a live runtime connection.

2. CHATGPT:
ThreatGuard AI uses Qwen 2.5:7b through Ollama.
It does not use OpenAI ChatGPT or the ChatGPT API unless
an actual integration is configured.

3. MONGODB:
MongoDB stores user accounts, chat history
and threat records.

4. FASTAPI:
FastAPI provides the backend API and handles application
requests, authentication and AI communication.

5. OLLAMA:
Ollama runs the local AI model Qwen 2.5:7b.

6. FRONTEND:
The frontend communicates with the FastAPI backend
through HTTP API requests.

YOUR CAPABILITIES:

You can answer questions about:
- General knowledge
- Artificial Intelligence
- Machine Learning
- Deep Learning
- Python, Java, C and C++
- HTML, CSS and JavaScript
- SQL and MongoDB
- Software development
- Operating systems
- Windows and Linux
- Networking
- Cybersecurity
- Ethical hacking concepts
- Malware awareness
- Phishing detection and prevention
- Password security
- Network security
- API development
- Database management
- Programming errors and debugging
- Computer science concepts

CYBERSECURITY RESPONSIBILITIES:

- Explain cybersecurity threats.
- Identify common attack techniques.
- Explain phishing and malware prevention.
- Recommend safe security practices.
- Explain vulnerabilities and their mitigation.
- Provide defensive security guidance.
- Never encourage unauthorized access or cybercrime.

ANSWERING RULES:

1. Answer the user's actual question.
2. Do not give unrelated answers.
3. Use simple, understandable language.
4. Provide detailed explanations when requested.
5. Use headings and numbered lists when useful.
6. Give practical examples.
7. For programming questions, provide working code.
8. Explain code step by step when requested.
9. For Yes/No questions, answer Yes or No first.
10. Never invent project features or connections.
11. Never claim a service is connected unless verified.
12. Distinguish development tools from runtime services.
13. If you do not know something, admit it.
14. Do not repeat the same information unnecessarily.
15. Maintain context throughout the conversation.

RESPONSE STYLE:

- Be friendly and professional.
- Be accurate and informative.
- Give clear answers.
- Avoid unnecessary technical complexity.
- Use examples wherever helpful.

You are ThreatGuard AI.
Your goal is to provide reliable answers,
help users understand technology and improve cybersecurity awareness.
"""


# ============================================================
# MONGODB CONNECTION
# ============================================================

mongo_client = MongoClient(
    MONGO_URI,
    serverSelectionTimeoutMS=3000
)

db = mongo_client[DATABASE_NAME]

users_collection = db["users"]
chat_collection = db["chat_history"]
threats_collection = db["threats"]


def check_mongodb():
    try:
        mongo_client.admin.command("ping")
        return True
    except Exception:
        return False


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="ThreatGuard AI API",
    description="AI-powered cybersecurity and general-purpose assistant",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:8000",
        "http://localhost:8000",
        "http://127.0.0.1:5500",
        "http://localhost:5500"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)


# ============================================================
# REQUEST MODELS
# ============================================================

class RegisterRequest(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(min_length=6, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=10000)


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def serialize_user(user):
    return {
        "id": str(user["_id"]),
        "name": user.get("name", ""),
        "email": user.get("email", "")
    }


def hash_password(password: str):
    return bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")


def verify_password(password: str, hashed_password: str):
    try:
        return bcrypt.checkpw(
            password.encode("utf-8"),
            hashed_password.encode("utf-8")
        )
    except (ValueError, TypeError):
        return False


def create_access_token(user):
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )

    payload = {
        "sub": str(user["_id"]),
        "email": user["email"],
        "exp": expire
    }

    return jwt.encode(
        payload,
        JWT_SECRET,
        algorithm=JWT_ALGORITHM
    )


def serialize_timestamp(value):
    if isinstance(value, datetime):
        return value.isoformat()

    return value


# ============================================================
# AUTHENTICATION
# ============================================================

def get_current_user(
    authorization: Optional[str] = Header(default=None)
):

    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Authorization token is missing."
        )

    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Invalid authorization format."
        )

    token = authorization.split(" ", 1)[1]

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM]
        )

        user_id = payload.get("sub")

        if not user_id or not ObjectId.is_valid(user_id):
            raise HTTPException(
                status_code=401,
                detail="Invalid user token."
            )

        user = users_collection.find_one({
            "_id": ObjectId(user_id)
        })

        if not user:
            raise HTTPException(
                status_code=401,
                detail="User account not found."
            )

        return user

    except JWTError:
        raise HTTPException(
            status_code=401,
            detail="Token expired or invalid. Please log in again."
        )


# ============================================================
# OLLAMA AI RESPONSE
# ============================================================

def generate_ai_response(message: str, user_id: str):

    try:

        history = list(
            chat_collection.find(
                {"user_id": user_id}
            ).sort("_id", -1).limit(10)
        )

        history.reverse()

        messages = [
            {
                "role": "system",
                "content": SYSTEM_PROMPT
            }
        ]

        for item in history:

            if item.get("user_message"):
                messages.append({
                    "role": "user",
                    "content": item["user_message"]
                })

            if item.get("ai_response"):
                messages.append({
                    "role": "assistant",
                    "content": item["ai_response"]
                })

        messages.append({
            "role": "user",
            "content": message
        })

        response = requests.post(
            f"{OLLAMA_URL}/api/chat",
            json={
                "model": MODEL,
                "messages": messages,
                "stream": False
            },
            timeout=180
        )

        response.raise_for_status()

        data = response.json()

        answer = data.get(
            "message", {}
        ).get("content", "")

        if not answer.strip():
            raise RuntimeError(
                "Ollama returned an empty response."
            )

        return answer.strip()

    except requests.exceptions.ConnectionError:
        raise HTTPException(
            status_code=503,
            detail="Ollama is not running. Please start Ollama."
        )

    except requests.exceptions.Timeout:
        raise HTTPException(
            status_code=504,
            detail="AI response timed out. Please try again."
        )

    except requests.exceptions.RequestException as error:
        raise HTTPException(
            status_code=502,
            detail=f"Ollama API error: {str(error)}"
        )


# ============================================================
# HOME
# ============================================================

@app.get("/")
def home():

    return {
        "success": True,
        "application": APP_NAME,
        "message": "ThreatGuard AI backend is running.",
        "backend": "FastAPI",
        "model": MODEL,
        "ai_engine": "Ollama",
        "database": DATABASE_NAME,
        "api_docs": "/docs"
    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health():

    return {
        "success": True,
        "status": "healthy",
        "application": APP_NAME,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


# ============================================================
# SYSTEM CONNECTION STATUS
# ============================================================

@app.get("/system-status")
def system_status():

    mongodb_connected = check_mongodb()

    ollama_connected = False
    model_available = False

    try:

        ollama_response = requests.get(
            f"{OLLAMA_URL}/api/tags",
            timeout=5
        )

        if ollama_response.status_code == 200:

            ollama_connected = True

            available_models = [
                item.get("name", "")
                for item in ollama_response.json().get("models", [])
            ]

            model_available = any(
                name == MODEL or name.startswith(MODEL + ":")
                for name in available_models
            )

    except requests.exceptions.RequestException:
        pass

    return {
        "application": APP_NAME,
        "timestamp": datetime.now(timezone.utc).isoformat(),

        "services": {

            "fastapi": {
                "status": "Connected",
                "connected": True,
                "message": "FastAPI backend is running."
            },

            "mongodb": {
                "status": (
                    "Connected" if mongodb_connected
                    else "Disconnected"
                ),
                "connected": mongodb_connected,
                "message": (
                    "MongoDB database is available."
                    if mongodb_connected
                    else "Cannot connect to MongoDB."
                )
            },

            "ollama": {
                "status": (
                    "Connected" if ollama_connected
                    else "Disconnected"
                ),
                "connected": ollama_connected
            },

            "ai_model": {
                "name": MODEL,
                "status": (
                    "Available" if model_available
                    else "Unavailable"
                ),
                "connected": model_available
            },

            "frontend": {
                "expected_port": 5500,
                "backend_port": 8001,
                "message": (
                    "Frontend communicates with FastAPI "
                    "through HTTP API requests."
                )
            },

            "visual_studio_code": {
                "status": "Development Environment",
                "connected": False,
                "message": (
                    "VS Code is used for development, "
                    "not as a live runtime service."
                )
            }
        }
    }


# ============================================================
# USER REGISTRATION
# ============================================================

@app.post("/register")
def register(request: RegisterRequest):

    try:

        email = request.email.lower().strip()

        existing_user = users_collection.find_one({
            "email": email
        })

        if existing_user:
            raise HTTPException(
                status_code=409,
                detail="An account with this email already exists."
            )

        user = {
            "name": request.name.strip(),
            "email": email,
            "password": hash_password(request.password),
            "created_at": datetime.now(timezone.utc)
        }

        result = users_collection.insert_one(user)

        user["_id"] = result.inserted_id

        token = create_access_token(user)

        return {
            "success": True,
            "message": "Registration successful.",
            "access_token": token,
            "token_type": "bearer",
            "user": serialize_user(user)
        }

    except HTTPException:
        raise

    except PyMongoError:
        raise HTTPException(
            status_code=503,
            detail="MongoDB is unavailable."
        )


# ============================================================
# USER LOGIN
# ============================================================

@app.post("/login")
def login(request: LoginRequest):

    try:

        email = request.email.lower().strip()

        user = users_collection.find_one({
            "email": email
        })

        if not user or not verify_password(
            request.password,
            user.get("password", "")
        ):

            raise HTTPException(
                status_code=401,
                detail="Invalid email or password."
            )

        token = create_access_token(user)

        return {
            "success": True,
            "message": "Login successful.",
            "access_token": token,
            "token_type": "bearer",
            "user": serialize_user(user)
        }

    except HTTPException:
        raise

    except PyMongoError:
        raise HTTPException(
            status_code=503,
            detail="MongoDB is unavailable."
        )


# ============================================================
# LOGOUT
# ============================================================

@app.post("/logout")
def logout(user=Depends(get_current_user)):

    return {
        "success": True,
        "message": "Logout successful. Please clear the stored token."
    }


# ============================================================
# CURRENT USER
# ============================================================

@app.get("/me")
def get_me(user=Depends(get_current_user)):

    return {
        "success": True,
        "user": serialize_user(user)
    }


# ============================================================
# AI CHAT
# ============================================================

@app.post("/chat")
def chat(
    request: ChatRequest,
    user=Depends(get_current_user)
):

    try:

        user_id = str(user["_id"])
        user_message = request.message.strip()

        if not user_message:
            raise HTTPException(
                status_code=400,
                detail="Please enter a message."
            )

        ai_response = generate_ai_response(
            user_message,
            user_id
        )

        chat_document = {
            "user_id": user_id,
            "email": user["email"],
            "user_message": user_message,
            "ai_response": ai_response,
            "timestamp": datetime.now(timezone.utc)
        }

        chat_collection.insert_one(chat_document)

        return {
            "success": True,
            "message": "AI response generated successfully.",
            "response": ai_response,
            "answer": ai_response
        }

    except HTTPException:
        raise

    except PyMongoError:
        raise HTTPException(
            status_code=503,
            detail="Unable to save chat history in MongoDB."
        )


# ============================================================
# CHAT HISTORY
# ============================================================

@app.get("/history")
def get_history(user=Depends(get_current_user)):

    records = list(
        chat_collection.find(
            {"user_id": str(user["_id"])}
        ).sort("_id", 1).limit(500)
    )

    history = []

    for record in records:

        history.append({
            "id": str(record["_id"]),
            "user_message": record.get("user_message", ""),
            "ai_response": record.get("ai_response", ""),
            "timestamp": serialize_timestamp(
                record.get("timestamp")
            )
        })

    return {
        "success": True,
        "history": history,
        "total": len(history)
    }


# ============================================================
# THREAT RECORDS
# ============================================================

@app.get("/threats")
def get_threats(
    platform: Optional[str] = None,
    user=Depends(get_current_user)
):

    try:

        user_id = str(user["_id"])

        # Support both string and ObjectId user IDs.
        query = {
            "user_id": {
                "$in": [user_id, user["_id"]]
            }
        }

        # Apply platform filter when requested.
        # Records without a platform field remain visible
        # for compatibility with older threat records.
        if platform and platform.lower() != "all":

            query["$or"] = [
                {
                    "platform": {
                        "$regex": f"^{platform}$",
                        "$options": "i"
                    }
                },
                {
                    "platform": {
                        "$exists": False
                    }
                },
                {
                    "platform": None
                }
            ]

        records = list(
            threats_collection.find(query)
            .sort("_id", -1)
            .limit(200)
        )

        threats = []

        for record in records:

            threats.append({
                "id": str(record["_id"]),

                "title": record.get(
                    "title",
                    record.get("type", "Unknown")
                ),

                "type": record.get(
                    "type",
                    "Unknown"
                ),

                "description": record.get(
                    "description",
                    ""
                ),

                "severity": record.get(
                    "severity",
                    "Unknown"
                ),

                "status": record.get(
                    "status",
                    "Open"
                ),

                "platform": record.get(
                    "platform",
                    "Unknown"
                ),

                "mitigation": record.get(
                    "mitigation",
                    []
                ),

                "timestamp": serialize_timestamp(
                    record.get("timestamp")
                )
            })

        return {
            "success": True,
            "threats": threats,
            "total": len(threats),
            "platform": platform or "All"
        }

    except PyMongoError:
        raise HTTPException(
            status_code=503,
            detail="Unable to retrieve threat records from MongoDB."
        )


# ============================================================
# STARTUP EVENT
# ============================================================

@app.on_event("startup")
def startup_event():

    print("=" * 55)
    print("       THREATGUARD AI BACKEND STARTING")
    print("=" * 55)

    print("Backend: FastAPI")
    print("Backend Port: 8001")
    print("AI Model:", MODEL)
    print("AI Engine: Ollama")
    print("Database:", DATABASE_NAME)

    print(
        "MongoDB:",
        "Connected" if check_mongodb() else "Disconnected"
    )

    print("=" * 55)


# ============================================================
# RUN SERVER
# ============================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=8001,
        reload=True
    )

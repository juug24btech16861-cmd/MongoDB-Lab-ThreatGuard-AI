
from pymongo import MongoClient, ASCENDING
from pymongo.errors import DuplicateKeyError
from datetime import datetime, timezone
import hashlib
import secrets
import hmac


# --------------------------------
# MONGODB CONNECTION
# --------------------------------

MONGO_URL = "mongodb://localhost:27017/"

client = MongoClient(
    MONGO_URL,
    serverSelectionTimeoutMS=5000
)

db = client["threatguard_db"]


# --------------------------------
# COLLECTIONS
# --------------------------------

chat_collection = db["chat_history"]
threat_collection = db["threats"]
vulnerability_collection = db["vulnerabilities"]
user_collection = db["users"]


# --------------------------------
# PASSWORD SECURITY
# --------------------------------

def hash_password(password, salt=None):

    if salt is None:
        salt = secrets.token_bytes(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        600000
    )

    return salt.hex(), password_hash.hex()


def verify_password(password, stored_salt, stored_hash):

    salt = bytes.fromhex(stored_salt)

    _, calculated_hash = hash_password(
        password,
        salt
    )

    return hmac.compare_digest(
        calculated_hash,
        stored_hash
    )


# --------------------------------
# USER REGISTRATION
# --------------------------------

def register_user(name, email, password):

    name = name.strip()
    email = email.strip().lower()

    if not name or not email or not password:
        return None

    if len(password) < 8:
        return None

    salt, password_hash = hash_password(password)

    user_data = {
        "name": name,
        "email": email,
        "password_salt": salt,
        "password_hash": password_hash,
        "created_at": datetime.now(timezone.utc)
    }

    try:

        result = user_collection.insert_one(user_data)

        return {
            "id": str(result.inserted_id),
            "name": name,
            "email": email
        }

    except DuplicateKeyError:

        return None


# --------------------------------
# USER LOGIN
# --------------------------------

def authenticate_user(email, password):

    email = email.strip().lower()

    user = user_collection.find_one({
        "email": email
    })

    if not user:
        return None

    valid_password = verify_password(
        password,
        user["password_salt"],
        user["password_hash"]
    )

    if not valid_password:
        return None

    return {
        "id": str(user["_id"]),
        "name": user["name"],
        "email": user["email"]
    }


# --------------------------------
# SAVE CHAT CONVERSATIONS
# --------------------------------

def save_chat(user_id, user_message, bot_response):

    chat_data = {
        "user_id": user_id,
        "user_message": user_message,
        "bot_response": bot_response,
        "timestamp": datetime.now(timezone.utc)
    }

    chat_collection.insert_one(chat_data)


# --------------------------------
# RETRIEVE USER CHAT HISTORY
# --------------------------------

def get_chat_history(user_id):

    return list(
        chat_collection.find(
            {"user_id": user_id},
            {"_id": 0}
        ).sort("timestamp", -1)
    )


# --------------------------------
# INSERT SAMPLE THREAT RECORDS
# --------------------------------

def initialize_threats():

    if threat_collection.count_documents({}) > 0:
        return

    sample_threats = [

        {
            "title": "Windows Malware Infection",
            "platform": "Windows",
            "status": "Active",
            "severity": "High",
            "description": "Malware can compromise files and system security.",
            "mitigation": [
                "Run a Microsoft Defender full scan.",
                "Quarantine detected malicious files.",
                "Install the latest security updates."
            ],
            "source": "Educational demonstration dataset",
            "sample_data": True
        },

        {
            "title": "Unpatched Windows Software",
            "platform": "Windows",
            "status": "Anticipated",
            "severity": "Medium",
            "description": "Outdated software may contain security weaknesses.",
            "mitigation": [
                "Check available software updates.",
                "Install security patches.",
                "Restart applications if required."
            ],
            "source": "Educational demonstration dataset",
            "sample_data": True
        },

        {
            "title": "Phishing Campaign",
            "platform": "Windows",
            "status": "Evolving",
            "severity": "High",
            "description": "Attackers may use deceptive emails to steal credentials.",
            "mitigation": [
                "Avoid suspicious email links.",
                "Enable multi-factor authentication.",
                "Report suspicious messages."
            ],
            "source": "Educational demonstration dataset",
            "sample_data": True
        },

        {
            "title": "Resolved Security Update Issue",
            "platform": "Windows",
            "status": "Resolved",
            "severity": "Low",
            "description": "A previously identified software update issue has been addressed in this demonstration.",
            "mitigation": [
                "Verify that the security update is installed.",
                "Check the system update history."
            ],
            "source": "Educational demonstration dataset",
            "sample_data": True
        }

    ]

    threat_collection.insert_many(sample_threats)


# --------------------------------
# RETRIEVE THREAT INFORMATION
# --------------------------------

def get_threats(platform="Windows", status=None):

    query = {
        "platform": platform
    }

    if status:
        query["status"] = status

    return list(
        threat_collection.find(
            query,
            {"_id": 0}
        )
    )


# --------------------------------
# SEARCH THREATS
# --------------------------------

def search_threats(keyword):

    return list(
        threat_collection.find(
            {
                "$or": [
                    {
                        "title": {
                            "$regex": keyword,
                            "$options": "i"
                        }
                    },
                    {
                        "description": {
                            "$regex": keyword,
                            "$options": "i"
                        }
                    },
                    {
                        "severity": {
                            "$regex": keyword,
                            "$options": "i"
                        }
                    }
                ]
            },
            {"_id": 0}
        )
    )


# --------------------------------
# CREATE DATABASE INDEXES
# --------------------------------

def create_indexes():

    threat_collection.create_index(
        [
            ("platform", ASCENDING),
            ("status", ASCENDING)
        ]
    )

    threat_collection.create_index(
        [("severity", ASCENDING)]
    )

    chat_collection.create_index(
        [
            ("user_id", ASCENDING),
            ("timestamp", ASCENDING)
        ]
    )

    user_collection.create_index(
        [("email", ASCENDING)],
        unique=True
    )


# --------------------------------
# INITIALIZE DATABASE
# --------------------------------

def initialize_database():

    client.admin.command("ping")

    initialize_threats()

    create_indexes()

    return "ThreatGuard AI database initialized successfully!"




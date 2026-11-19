
import os
import requests
from dotenv import load_dotenv

load_dotenv()

OLLAMA_URL = os.getenv(
    "OLLAMA_BASE_URL",
    "http://localhost:11434"
)

MODEL = os.getenv("LLM_MODEL", "llama3.2:3b")


def generate_answer(messages):
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
    result = response.json()

    return result["message"]["content"]


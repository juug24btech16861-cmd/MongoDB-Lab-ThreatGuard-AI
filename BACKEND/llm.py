
import os
import requests
from dotenv import load_dotenv

load_dotenv()

OLLAMA_URL = os.getenv(
    "OLLAMA_BASE_URL",
    "http://127.0.0.1:11434"
)

MODEL = os.getenv("LLM_MODEL", "qwen2.5:7b")


def generate_answer(messages):

    try:
        response = requests.post(
            f"{OLLAMA_URL}/api/chat",
            json={
                "model": MODEL,
                "messages": messages,
                "stream": False,
                "options": {
                    "temperature": 0.7,
                    "num_predict": 1500
                }
            },
            timeout=(10, 240)
        )

        response.raise_for_status()

        result = response.json()

        return result["message"]["content"]

    except requests.exceptions.Timeout:
        return "The AI is taking too long to respond. Please try again."

    except requests.exceptions.ConnectionError:
        return "Cannot connect to Ollama. Please check whether Ollama is running."

    except requests.exceptions.RequestException as error:
        return f"AI service error: {str(error)}"

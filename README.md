# 🛡️ ThreatGuard AI – MongoDB Lab Project

## 📌 Project Overview

ThreatGuard AI is an AI-powered cybersecurity chatbot developed to help users understand common cybersecurity threats and learn how to protect themselves online.

The chatbot provides information about cybersecurity topics such as phishing, security updates, and possible threat mitigation methods. It uses database records to provide relevant information and AI-based responses to user queries.

## 🎯 Objectives

- To create an interactive cybersecurity chatbot.
- To help users understand common cyber threats.
- To provide information about phishing attacks and prevention methods.
- To store and retrieve cybersecurity-related information using MongoDB.
- To provide recommendations for improving security awareness.

## ✨ Features

- **AI Chatbot:** Answers cybersecurity-related questions.
- **Phishing Awareness:** Explains phishing attacks and prevention techniques.
- **Threat Information:** Provides information about security threats.
- **MongoDB Integration:** Uses database records to retrieve relevant information.
- **Security Recommendations:** Suggests possible steps to improve security.
- **User-Friendly Interface:** Provides an interactive chatbot experience.

## 🛠️ Technologies Used

- Python
- MongoDB
- Streamlit
- Artificial Intelligence / LLM
- HTML and CSS (where applicable)

## 📂 Project Structure

```text
MongoDB-Lab-ThreatGuard-AI/
│
├── BACKEND/
│   ├── llm.py
│   └── main.py
│
├── FRONTEND/
│   └── app.py
│
└── .gitignore
```

## ⚙️ Installation and Setup

### 1. Clone the Repository

```bash
git clone https://github.com/juug24btech16861-cmd/MongoDB-Lab-ThreatGuard-AI.git
```

### 2. Open the Project Folder

```bash
cd MongoDB-Lab-ThreatGuard-AI
```

### 3. Create a Virtual Environment

```bash
python -m venv venv
```

### 4. Activate the Virtual Environment

For Windows:

```bash
venv\Scripts\activate
```

### 5. Install Dependencies

Install the packages listed in your project's requirements file:

```bash
pip install -r requirements.txt
```

If your project does not yet contain a `requirements.txt`, create one with the dependencies actually used by your code.

### 6. Configure Environment Variables

Add the required MongoDB connection details and AI API key to a local `.env` file, according to your backend configuration.

Do not upload passwords, API keys, or database credentials to GitHub.

### 7. Run the Application

Run the backend and frontend using the commands configured in your project.

For a Streamlit frontend, the command may be:

```bash
streamlit run FRONTEND/app.py
```

## 🔐 Important Note

ThreatGuard AI provides cybersecurity information and recommendations based on available database records and AI-generated responses. It does not perform live security scans of the user's computer or automatically execute security updates or mitigation actions.

## 🚀 Future Enhancements

- Real-time threat intelligence integration.
- Improved phishing URL detection.
- More cybersecurity datasets.
- Enhanced chatbot response accuracy.
- User authentication and chat history.

## 👩‍💻 Project Information

**Project Name:** ThreatGuard AI

**Domain:** Cybersecurity and Database Management

**Repository:** [MongoDB-Lab-ThreatGuard-AI](https://github.com/juug24btech16861-cmd/MongoDB-Lab-ThreatGuard-AI)

## 📜 Conclusion

ThreatGuard AI demonstrates how artificial intelligence and MongoDB can be used together to create an interactive cybersecurity chatbot. It helps users learn about common online threats and understand suitable security practices.

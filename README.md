# 🛡️ Link Suraksha

### Smart Fraud Link Detection for Safer Digital Communication

**Built for AI Kavach 2026**

Link Suraksha is a lightweight fraud-link detection tool designed to help users identify suspicious links before clicking them. It analyzes URLs and messages for common fraud and phishing indicators and provides a simple, easy-to-understand safety verdict.

## 🚀 Live Demo

👉 **Try Link Suraksha:**
https://linksuraksha.streamlit.app/

---

## 🎯 The Problem

Fraudulent links are increasingly shared through platforms such as WhatsApp, SMS, and social media.

Many suspicious messages are designed to look genuine by using:

* Fake banking or payment pages
* Urgent account warnings
* Reward and lottery claims
* KYC verification requests
* Suspicious shortened URLs
* Fake government or service notifications

For users who are not familiar with cybersecurity, identifying these links can be difficult.

## 💡 Our Solution

**Link Suraksha** provides a simple way to check a suspicious link before interacting with it.

The system:

1. Accepts a URL or suspicious message.
2. Extracts and analyzes the link.
3. Checks for known fraud indicators using rule-based detection.
4. Optionally uses external threat-intelligence services for additional verification.
5. Generates a clear **SAFE / SUSPICIOUS / FRAUD** verdict.
6. Provides the result in English and Odia.
7. Supports a voice alert for improved accessibility.

---

## ⚙️ How It Works

```text
User enters a suspicious link
            ↓
     URL / Message Analysis
            ↓
     Fraud Pattern Detection
            ↓
   Threat Intelligence Check
            ↓
      Risk Assessment
            ↓
   ┌────────┴────────┐
   ↓                 ↓
 SAFE / SUSPICIOUS   FRAUD
   ↓                 ↓
 English + Odia + Voice Alert
```

---

## 🔍 Detection Features

Link Suraksha checks for multiple suspicious patterns, including:

* 🔗 Suspicious URL structures
* 🎭 Possible brand impersonation
* 🔐 Fake login or verification pages
* 💰 Financial scam indicators
* 🎁 Reward and lottery scams
* 📱 KYC-related fraud patterns
* ⚠️ Urgency and threat-based messages
* 🌐 Suspicious domains and URL characteristics
* 🔎 Optional external threat-intelligence verification

---

## 🧠 Technology Stack

| Technology               | Purpose                      |
| ------------------------ | ---------------------------- |
| Python                   | Core application logic       |
| Streamlit                | Interactive web application  |
| Regex                    | Fraud-pattern detection      |
| VirusTotal API           | Optional threat intelligence |
| Google Safe Browsing API | Optional URL verification    |
| Translation              | English → Odia results       |
| Edge TTS                 | Odia voice alert             |

---

## 📊 Prototype Evaluation

The prototype was evaluated using a separate set of labelled test URLs.

**Current evaluation:**

* **50 test links**
* **47 correctly classified**
* **94% observed accuracy**
* **~1.8 seconds average checking time**

> These results are prototype evaluation results on the project's test dataset and should not be interpreted as a universal real-world accuracy guarantee.

---

## 📁 Project Structure

```text
link-suraksha/
│
├── app.py
├── detector.py
├── threat_intelligence.py
├── translator.py
├── voice.py
├── config.py
├── utils.py
│
├── data/
│   ├── sample_urls.csv
│   └── evaluation_urls.csv
│
├── evaluation/
│   └── evaluate.py
│
├── requirements.txt
└── README.md
```

---

## 🔑 Optional API Configuration

The core rule-based detector can run without external API keys.

For enhanced verification, optional API credentials can be configured for:

* **VirusTotal**
* **Google Safe Browsing**

Example environment variables:

```text
VIRUSTOTAL_API_KEY=your_api_key
GOOGLE_SAFE_BROWSING_API_KEY=your_api_key
```

**Never commit real API keys to GitHub.**

---

## 🧪 Dataset

The project includes self-authored/synthetic labelled URL datasets for prototype testing and evaluation.

The datasets contain examples labelled as **SAFE** and **FRAUD** and are intended for demonstration and evaluation of the prototype.

---

## 🌍 Social Impact

Link Suraksha aims to make basic digital safety easier to understand and access, especially for users who may not have a technical cybersecurity background.

The goal is simple:

> **Check before you click. Stay safe online.**

---

## 🚀 Future Scope

Planned improvements include:

* 📈 Larger and more diverse real-world datasets
* 🤖 ML-based risk classification
* 🌐 Support for additional Indian languages
* 📱 Progressive Web App / mobile application
* 🛡️ Real-time threat intelligence
* 🔔 Browser and messaging-platform integration
* ♿ Improved accessibility features

---

## 🏆 Hackathon

**AI Kavach 2026**

Link Suraksha was developed as a cybersecurity-focused prototype for **AI Kavach 2026**, with the aim of helping users identify potentially fraudulent links before they become victims of online scams.

---

## 👩‍💻 Built By

**Debangana Dutta**
B.Tech CSE | XIM University, Bhubaneswar

---

## 🔗 Links

**Live Demo:**
https://linksuraksha.streamlit.app/

**GitHub Repository:**
https://github.com/Debangana-Dutta/link-suraksha

---

### ⚠️ Disclaimer

Link Suraksha is a prototype intended to assist users in identifying potentially suspicious links. A **SAFE** result does not guarantee that a URL is completely safe, and users should always exercise caution before sharing credentials, OTPs, banking information, or personal data.

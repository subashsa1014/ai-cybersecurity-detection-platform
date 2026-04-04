# 🛡️ AI Cybersecurity Detection Platform

A comprehensive AI-powered system for detecting malware, identifying phishing URLs, and scanning files for threats. Built with FastAPI, React, and Machine Learning.

## 📋 Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Quick Start](#quick-start)
- [Phases](#phases)
- [Advanced Features](#advanced-features)
- [Getting Help](#getting-help)

## 🚀 Overview

This platform provides a complete solution for cybersecurity threat detection combining:
- **Machine Learning Models** for intelligent threat identification
- **Real-time API** for instant scanning
- **Professional Dashboard** for threat monitoring
- **User Authentication** for secure access

Like a mini antivirus + security platform! 🔥

## ✨ Features

### Phase 1: URL Phishing Detector
- ✅ Input URL and get instant analysis
- ✅ Risk score calculation (0-100%)
- ✅ Explainable AI showing why a URL is flagged
- ✅ Domain, length, HTTPS, and pattern analysis

### Phase 2: File Scanner
- ✅ Upload files (.exe, .pdf, .zip, etc.)
- ✅ Signature-based detection
- ✅ AI-based malware detection
- ✅ Visual threat level indicators (🟢 Safe / 🟡 Suspicious / 🔴 Dangerous)

### Phase 3: Malware Detection + Dashboard
- ✅ XGBoost/Random Forest based detection
- ✅ Threat Intelligence Dashboard
- ✅ User authentication (JWT)
- ✅ Scan history tracking
- ✅ Alert system with risk levels

### Advanced Features 🔥
- ✅ Real-time Scan API with FastAPI
- ✅ Explainable AI (feature importance)
- ✅ User authentication & scan history
- ✅ Alert system with risk visualization
- ✅ Swagger API documentation

## 📦 Tech Stack

| Layer | Technology |
|-------|-----------|
| **Frontend** | React.js, Tailwind CSS |
| **Backend** | FastAPI (Python) |
| **ML/AI** | Scikit-learn, XGBoost |
| **Database** | MongoDB |
| **Authentication** | JWT |
| **Documentation** | Swagger/OpenAPI |

## 📁 Project Structure

```
cyber-security-app/
├── frontend/               # React dashboard & UI
│   ├── src/
│   │   ├── components/     # React components
│   │   ├── pages/          # Page components
│   │   └── App.jsx
│   └── package.json
├── backend/                # FastAPI backend
│   ├── app.py              # Main application
│   ├── routes/             # API endpoints
│   ├── models/             # Data models
│   ├── utils/              # Utility functions
│   ├── requirements.txt
│   └── .env.example
├── ml-model/               # Machine Learning
│   ├── train_phishing_model.py
│   ├── train_malware_model.py
│   └── requirements.txt
├── dataset/                # Data files
│   ├── phishing_urls.csv
│   └── malware_samples/
├── docs/                   # Documentation
│   ├── SETUP.md
│   ├── API.md
│   └── ARCHITECTURE.md
└── README.md
```

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Node.js 14+
- MongoDB (local or Atlas)
- Git

### Backend Setup
```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python app.py
```

Backend runs on: `http://localhost:8000`

### Frontend Setup
```bash
cd frontend
npm install
npm start
```

Frontend runs on: `http://localhost:3000`

### ML Model Setup
```bash
cd ml-model
pip install -r requirements.txt
python train_phishing_model.py
```

📚 **Full setup guide:** See [docs/SETUP.md](docs/SETUP.md)

## 📊 Phases

### Phase 1️⃣ - URL Phishing Detector (START HERE)
- URL input form
- FastAPI backend endpoint
- XGBoost model for phishing detection
- Risk score + explanation
- **Timeline:** 1-2 weeks

**Issues:** Track with GitHub Issues labeled `phase 1`

### Phase 2️⃣ - File Scanner
- File upload functionality
- Signature-based detection
- ML-based file analysis
- Threat visualization
- **Timeline:** 2-3 weeks

**Issues:** Track with GitHub Issues labeled `phase 2`

### Phase 3️⃣ - Full Platform + Dashboard
- User authentication (JWT)
- Threat Intelligence Dashboard
- Scan history
- Alert system
- Dark mode
- **Timeline:** 3-4 weeks

**Issues:** Track with GitHub Issues labeled `phase 3`

## 🔥 Advanced Features

- **Real-Time API** - FastAPI with instant results
- **Explainable AI** - Understand why something is flagged
- **User History** - Track your scans over time
- **Alert System** - Risk color codes (🟢 🟡 🔴)
- **Swagger Docs** - Professional API documentation
- **Dark Mode** - Eye-friendly interface

## 📌 Bonus Features (To Stand Out!)

- [ ] Chrome Extension for live URL scanning
- [ ] Public API with rate limiting
- [ ] Dark mode dashboard
- [ ] Advanced threat analytics
- [ ] Email alerts

## 📖 Documentation

- **[SETUP.md](docs/SETUP.md)** - Detailed setup instructions
- **[API.md](docs/API.md)** - API endpoints reference
- **[ARCHITECTURE.md](docs/ARCHITECTURE.md)** - System architecture diagram

## 🔗 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | API status |
| GET | `/health` | Health check |
| POST | `/api/scan-url` | Scan URL for phishing |
| POST | `/api/scan-file` | Scan file for malware |
| GET | `/api/dashboard/threats` | Get threat statistics |

Full documentation available at: `http://localhost:8000/docs`

## 🎯 Learning Outcomes

By building this project, you'll demonstrate:
- ✅ Cybersecurity knowledge
- ✅ AI/ML skills (XGBoost, feature engineering)
- ✅ Full-stack development (React + FastAPI)
- ✅ Real-world problem solving
- ✅ Professional software architecture

💡 **This is exactly what companies like McAfee, CrowdStrike, and Palo Alto Networks look for!**

## 🤝 Contributing

Contributions are welcome! Please follow these steps:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see LICENSE file for details.

## 📧 Getting Help

- 📚 Check [docs/](docs/) for detailed guides
- 🐛 Open an issue for bugs or questions
- 💬 Discussions are open for ideas and questions

## 🌟 Show Your Support

If you found this helpful, please star the repository! ⭐

---

**Built with ❤️ for cybersecurity enthusiasts**

*Happy coding and stay secure! 🔐*
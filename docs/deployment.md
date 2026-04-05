# Deployment Guide

## Table of Contents

- [Local Development](#local-development)
- [Docker Deployment](#docker-deployment)
- [Cloud Deployment (Render)](#cloud-deployment-render)
- [Cloud Deployment (Railway)](#cloud-deployment-railway)
- [Production Checklist](#production-checklist)
- [Troubleshooting](#troubleshooting)

---

## Local Development

### Prerequisites

- Python 3.11 or higher
- MongoDB 7.0 or MongoDB Atlas account
- Git

### Setup Steps

1. **Clone the repository**
   ```bash
   git clone https://github.com/subashsa1014/ai-cybersecurity-detection-platform.git
   cd ai-cybersecurity-detection-platform
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   venv\Scripts\activate     # Windows
   ```

3. **Install dependencies**
   ```bash
   cd backend
   pip install -r requirements.txt
   ```

4. **Configure environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your MongoDB URI and secret key
   ```

5. **Start MongoDB** (if running locally)
   ```bash
   mongod --dbpath /data/db
   ```

6. **Run the application**
   ```bash
   uvicorn app:app --reload --host 0.0.0.0 --port 8000
   ```

7. **Access the API**
   - API: http://localhost:8000
   - Swagger Docs: http://localhost:8000/docs
   - ReDoc: http://localhost:8000/redoc

---

## Docker Deployment

### Prerequisites

- Docker 24.0+
- Docker Compose 2.20+

### Quick Start

1. **Build and start all services**
   ```bash
   docker-compose up --build
   ```

2. **Start in detached mode**
   ```bash
   docker-compose up -d
   ```

3. **View logs**
   ```bash
   docker-compose logs -f
   ```

4. **Stop all services**
   ```bash
   docker-compose down
   ```

5. **Stop and remove volumes**
   ```bash
   docker-compose down -v
   ```

### Production with Nginx

```bash
docker-compose --profile production up -d
```

### Accessing Services

| Service | URL |
|---------|-----|
| Backend API | http://localhost:8000 |
| MongoDB | mongodb://localhost:27017 |
| Nginx (prod) | http://localhost:80 |

---

## Cloud Deployment (Render)

### Step 1: Prepare Your Repository

Ensure your repository has:
- `Dockerfile` in the root
- `requirements.txt` in `backend/`
- `.env` variables configured in Render dashboard

### Step 2: Create a Web Service on Render

1. Go to [Render Dashboard](https://dashboard.render.com)
2. Click **New** > **Web Service**
3. Connect your GitHub repository
4. Configure:
   - **Name**: ai-cybersecurity-platform
   - **Region**: Choose closest to your users
   - **Branch**: main
   - **Root Directory**: backend
   - **Runtime**: Docker
   - **Docker Command**: `uvicorn app:app --host 0.0.0.0 --port $PORT`

### Step 3: Environment Variables

Set these in Render dashboard:

```
MONGODB_URI=mongodb+srv://<user>:<password>@cluster.mongodb.net/cybersecurity_platform
SECRET_KEY=<your-production-secret-key>
ACCESS_TOKEN_EXPIRE_MINUTES=30
```

### Step 4: MongoDB Atlas Setup

1. Create a free cluster at [MongoDB Atlas](https://cloud.mongodb.com)
2. Create a database user
3. Whitelist `0.0.0.0/0` for Render access
4. Get the connection string and set it as `MONGODB_URI`

### Step 5: Deploy

Click **Create Web Service**. Render will build and deploy automatically.

---

## Cloud Deployment (Railway)

### Step 1: Connect Repository

1. Go to [Railway](https://railway.app)
2. Click **New Project** > **Deploy from GitHub**
3. Select your repository

### Step 2: Configure Build

- **Root Directory**: `backend`
- **Start Command**: `uvicorn app:app --host 0.0.0.0 --port $PORT`

### Step 3: Set Environment Variables

In Railway variables tab:

```
MONGODB_URI=<your-mongodb-connection-string>
SECRET_KEY=<your-secret-key>
PORT=8000
```

### Step 4: Deploy

Railway will automatically deploy. Access via the generated URL.

---

## Production Checklist

### Security

- [ ] Use strong, unique `SECRET_KEY`
- [ ] Enable HTTPS/TLS
- [ ] Set up firewall rules
- [ ] Use environment variables for all secrets
- [ ] Enable rate limiting
- [ ] Set up CORS properly
- [ ] Use non-root Docker user
- [ ] Keep dependencies updated

### Performance

- [ ] Use multiple uvicorn workers
- [ ] Enable gzip compression
- [ ] Set up CDN for static assets
- [ ] Configure connection pooling for MongoDB
- [ ] Set up caching layer (Redis)

### Monitoring

- [ ] Set up logging (structured JSON logs)
- [ ] Configure health checks
- [ ] Set up uptime monitoring
- [ ] Configure error tracking (Sentry)
- [ ] Set up metrics collection (Prometheus)

### Backup

- [ ] Configure MongoDB automated backups
- [ ] Set up database snapshot schedule
- [ ] Test backup restoration process

---

## Troubleshooting

### Common Issues

**Port already in use**
```bash
lsof -i :8000
kill -9 <PID>
```

**MongoDB connection failed**
- Check MongoDB URI format
- Verify network connectivity
- Ensure MongoDB is running

**Module not found**
```bash
pip install -r requirements.txt
```

**Docker build fails**
```bash
docker system prune -a
docker-compose build --no-cache
```

**CORS errors**
- Check CORS settings in `app.py`
- Ensure frontend origin is in allowed list

### Logs

**View Docker logs**
```bash
docker-compose logs backend
```

**View application logs**
```bash
docker-compose logs -f backend
```

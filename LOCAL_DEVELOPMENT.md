# 🛡️ Sentinel Protocol - Local Development Guide

## ✅ Applications are Currently Running

Both frontend and backend are now successfully hosted locally!

### 🌐 Access URLs

- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs
- **API ReDoc**: http://localhost:8000/redoc

---

## 🔧 Configuration Changes Made

### Backend Configuration
1. **CORS Settings** - Updated to allow connections from frontend:
   - Location: `backend/app/core/config.py`
   - Allowed origins: `http://localhost:3000`, `http://127.0.0.1:3000`

2. **Environment Variables** - Updated `.env` file:
   - Fixed `CEREBRAS_API_KEY` configuration
   - Database, blockchain, and API keys are properly configured

### Frontend Configuration
3. **API Connection** - Already configured correctly:
   - Location: `frontend/.env.local`
   - API URL: `http://localhost:8000`

---

## 🚀 How to Start Services (Next Time)

### Option 1: Start Both Services Together
```powershell
# From the sentinel-protocol directory
.\start-local.ps1
```

### Option 2: Start Services Separately

#### Start Backend:
```powershell
cd "d:\New folder\sentinel-protocol\backend"
.\venv\Scripts\Activate.ps1
python main.py
```

#### Start Frontend (in a new terminal):
```powershell
cd "d:\New folder\sentinel-protocol\frontend"
npm run dev
```

---

## 📋 Current Status

| Service  | Status | URL | Port |
|----------|--------|-----|------|
| Backend  | ✅ Running | http://localhost:8000 | 8000 |
| Frontend | ✅ Running | http://localhost:3000 | 3000 |

---

## 🛑 How to Stop Services

- Press `Ctrl+C` in each terminal window
- Or close the terminal windows

---

## 🔍 Testing the Connection

1. Open your browser and go to: http://localhost:3000
2. The frontend should load the Sentinel Protocol interface
3. Try analyzing a contract to test the backend connection
4. Check API docs at: http://localhost:8000/docs

---

## 📁 Project Structure

```
sentinel-protocol/
├── backend/               # FastAPI backend (Python)
│   ├── main.py           # Entry point
│   ├── .env              # Environment variables
│   └── venv/             # Python virtual environment
├── frontend/             # Next.js frontend (TypeScript)
│   ├── .env.local        # Frontend environment variables
│   └── app/              # Next.js pages
└── start-local.ps1       # Unified startup script
```

---

## ⚙️ Environment Variables

### Backend (.env)
- `CEREBRAS_API_KEY` - LLM API key
- `ALCHEMY_API_KEY` - Blockchain RPC
- `DATABASE_URL` - PostgreSQL connection
- `ETHERSCAN_API_KEY` - Block explorer APIs
- `CORS_ORIGINS` - Allowed frontend origins

### Frontend (.env.local)
- `NEXT_PUBLIC_API_URL` - Backend API URL

---

## 🐛 Troubleshooting

### Backend Issues
- **Module not found**: Activate virtual environment first
  ```powershell
  .\venv\Scripts\Activate.ps1
  ```
- **Port in use**: Kill process on port 8000 or change PORT in .env
- **API key errors**: Check .env file has all required keys

### Frontend Issues
- **Dependencies missing**: Run `npm install`
- **Port in use**: Frontend will ask to use different port
- **API connection failed**: Check backend is running on port 8000

---

## 📊 API Endpoints

Test these endpoints in your browser or API client:

- `GET /` - API welcome message
- `GET /api/v1/health` - Health check
- `POST /api/v1/analyze` - Analyze contract
- `POST /api/v1/analyze/source` - Analyze source code
- `GET /api/v1/history` - Analysis history
- `GET /api/v1/stats` - Statistics

---

## 🎉 Next Steps

1. Visit http://localhost:3000 to use the application
2. Try analyzing a smart contract
3. Check the API documentation at http://localhost:8000/docs
4. Review the analysis results and trust scores

---

**Note**: Both services must be running for the application to work properly. The frontend communicates with the backend API to perform contract analysis.

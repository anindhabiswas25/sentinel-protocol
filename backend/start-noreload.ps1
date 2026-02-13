$env:CEREBRAS_API_KEY="csk-cn8np5nmekypdhf5xj3t8er6x8ymy5x8nf86hvxf9364jtfn"
$env:ALCHEMY_API_KEY="9Ch0jThF1t4lxLVQxk0Uk"
$env:DATABASE_URL="postgresql://neondb_owner:npg_lA7qXNHZS0tm@ep-proud-queen-ai2iqcag-pooler.c-4.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require"
$env:ETHERSCAN_API_KEY="UM7VAXAARF5UBT5ZKJF7W56GCNMPBD4VU7"

Write-Host "Starting Sentinel Protocol Backend with Cerebras (1000 RPM)..."
.\venv\Scripts\python.exe -m uvicorn main:app --host 0.0.0.0 --port 8000

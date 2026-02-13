$env:CEREBRAS_API_KEY="csk-cn8np5nmekypdhf5xj3t8er6x8ymy5x8nf86hvxf9364jtfn"
$env:ALCHEMY_API_KEY="9Ch0jThF1t4lxLVQxk0Uk"
$env:DATABASE_URL="postgresql://neondb_owner:npg_wKq6ruYI0zlB@ep-proud-queen-ai2iqcag-pooler.us-east-1.aws.neon.tech/neondb?sslmode=require"
$env:ETHERSCAN_API_KEY="UM7VAXAARF5UBT5ZKJF7W56GCNMPBD4VU7"

Write-Host "Starting Sentinel Protocol Backend..."
.\venv\Scripts\python.exe main.py

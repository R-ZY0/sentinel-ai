from fastapi import FastAPI

app = FastAPI(title="Sentinel AI")


@app.get("/health")
def health():
    return {"status": "ok", "service": "sentinel-api"}
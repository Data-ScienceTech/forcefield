"""FastAPI app protected by ForceField.

Run:
    pip install forcefield[ml,fastapi] uvicorn
    uvicorn app:app --reload

All POST/PUT/PATCH requests are scanned automatically.
Blocked prompts return 403 with threat details.
"""

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from forcefield.integrations.fastapi import ForceFieldMiddleware

app = FastAPI(title="ForceField Protected API")
app.add_middleware(ForceFieldMiddleware, sensitivity="high")


@app.post("/chat")
async def chat(request: Request):
    body = await request.json()
    user_msg = body.get("message", "")
    return {"response": f"Echo: {user_msg}"}


@app.post("/summarize")
async def summarize(request: Request):
    body = await request.json()
    text = body.get("text", "")
    return {"summary": text[:100] + "..."}


@app.get("/health")
async def health():
    return {"status": "ok", "protection": "forcefield"}

"""FastAPI wrapper exposing the core password analysis logic as an HTTP API."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from src.core.passphrase_generator import generate_passphrase
from src.core.scorer import analyze_password
from src.report_generator import report_to_dict

app = FastAPI(
    title="Password Strength Checker + Analyzer API",
    description="Entropy, pattern, breach, and compliance analysis.",
    version="1.0.0",
)

# Permissive CORS for local development / demo purposes only.
# Restrict allow_origins before any real deployment.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


class AnalyzeRequest(BaseModel):
    password: str = Field(..., min_length=1)
    username: str | None = Field(None, description="For context-aware checks")
    email: str | None = Field(None, description="For context-aware checks")
    check_breaches: bool = Field(True, description="Check Have I Been Pwned")


class GenerateRequest(BaseModel):
    word_count: int = Field(6, ge=1, le=20)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/analyze")
def analyze(request: AnalyzeRequest) -> dict:
    report = analyze_password(
        request.password,
        username=request.username,
        email=request.email,
        check_breaches=request.check_breaches,
    )
    return report_to_dict(report)


@app.post("/generate")
def generate(request: GenerateRequest) -> dict:
    result = generate_passphrase(word_count=request.word_count)
    return {
        "passphrase": result.passphrase,
        "word_count": result.word_count,
        "wordlist_size": result.wordlist_size,
        "entropy_bits": result.entropy_bits,
    }

# Password Strength Checker + Analyzer



![CI](https://github.com/abdullah-alzghoul/password-strength-checker/actions/workflows/ci.yml/badge.svg)



A security tool that scores password strength using entropy analysis, weak-pattern detection, mutation simulation, real-world breach checking, and compliance auditing against named policy standards — built as a cybersecurity portfolio project. Available as a CLI, an HTTP API, and a browser demo.

## Features

- **Entropy-based scoring** — Shannon entropy from actual character-set diversity, not a naive length check
- **Pattern detection** — common passwords, sequential runs, keyboard walks, repeated characters, leetspeak substitutions, and username/email context matching
- **Mutation simulation** — tests the password against common cracking rules (case changes, suffixes, reversal, leetspeak) applied to a wordlist, similar in spirit to hashcat rule attacks
- **Effective entropy + score breakdown** — raw entropy reduced by every detected weakness, with a full line-item breakdown of where the points went
- **Breach checking** — Have I Been Pwned via the k-anonymity model: only a 5-character hash prefix ever leaves the machine
- **Compromised override** — a breached password is flagged `Compromised` regardless of entropy, per NIST SP 800-63B
- **Crack-time estimation** — human-readable time-to-crack under three attack scenarios
- **Compliance matrix** — pass/fail against NIST SP 800-63B, PCI DSS v4.0, and Active Directory default policy simultaneously
- **Passphrase generator** — cryptographically secure (`secrets` module) Diceware-style passphrases
- **Three interfaces** — interactive CLI, flag-driven CLI (single check / batch file / generate), and a FastAPI HTTP service with a browser demo
- **JSON, HTML, and PDF reports**, plus CSV summaries for batch runs — no plaintext password is ever written to any output

## Sample output

```text
Enter a password to analyze:
╭─────────────────────────────── Password Analysis ────────────────────────────────╮
│  Length             11                                                           │
│  Raw entropy        56.87 bits                                                   │
│  Effective entropy  6.87 bits                                                    │
│  Strength           Compromised                                                  │
╰────────────────────────────────────────────────────────────────────────────────╯
Strength ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   0%

Warnings:
  • Found in 2,266,543 known data breaches — do not use this password
  • One of the most common passwords (matched: password123)
  • Contains a predictable sequence: 123
  • Contains a predictable keyboard pattern: 123
```

## How it works

1. **`entropy.py`** calculates raw Shannon entropy and classifies it into a strength tier.
2. **`pattern_detector.py`** checks common-password/leetspeak matches, sequential runs, keyboard walks, repeated characters, and username/email context — each weakness carries a penalty.
3. **`mutation_simulator.py`** tests whether the password is a rule-based derivative of a wordlist entry.
4. **`scorer.py`** combines everything: `effective_entropy = raw_entropy − penalties`. A confirmed breach overrides the result to `Compromised` outright.
5. **`breach_checker.py`** implements the HIBP k-anonymity flow.
6. **`crack_time.py`** converts effective entropy into estimated crack time under three attack-speed assumptions.
7. **`compliance.py`** checks the password against three named policy standards independently.
8. **`report_generator.py`** serializes results to JSON, HTML, and PDF.
9. **`api.py`** exposes the same core functions over HTTP with no logic duplication.

## Installation

```powershell
git clone https://github.com/abdullah-alzghoul/password-strength-checker.git
cd password-strength-checker
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
```

## Usage

**Interactive:**
```powershell
python -m src.cli
```

**Single check (non-interactive):**
```powershell
python -m src.cli -p "TestPassword123!" -u abdullah --no-network
```

**Batch file:**
```powershell
python -m src.cli -f passwords.txt --no-network -o batch_results
```

**Generate a passphrase:**
```powershell
python -m src.cli -g -w 6
```

Run `python -m src.cli --help` for the full flag list.

## API + Web Demo

```powershell
fastapi dev src/api.py
```

Interactive API docs (Swagger UI) at `http://127.0.0.1:8000/docs`. For the browser demo, open `web/index.html` directly in any browser while the API is running.

## Docker

```powershell
docker build -t password-checker .
docker run -it --rm password-checker -p "TestPassword123!" --no-network
```

## Project structure

```text
password-checker/
├── .github/workflows/
│   └── ci.yml
├── src/
│   ├── core/
│   │   ├── entropy.py
│   │   ├── pattern_detector.py
│   │   ├── breach_checker.py
│   │   ├── mutation_simulator.py
│   │   ├── compliance.py
│   │   ├── crack_time.py
│   │   ├── passphrase_generator.py
│   │   └── scorer.py
│   ├── cli.py
│   ├── api.py
│   └── report_generator.py
├── web/
│   └── index.html
├── tests/
│   └── (one test file per module above)
├── data/
│   ├── common_passwords.txt
│   └── passphrase_words.txt
├── Dockerfile
├── .dockerignore
├── .pre-commit-config.yaml
├── pyproject.toml
├── requirements.txt
├── requirements-dev.txt
└── README.md
```

## Testing

160 unit and integration tests, including mocked network calls (no test hits a live API):

```powershell
python -m pytest tests/ -v
```

Linting and type-checking:
```powershell
ruff check .
mypy src/ --ignore-missing-imports
```

Both also run automatically via pre-commit on every commit, and via GitHub Actions on every push.

## Security notes

- No plaintext password is ever written to a log, report, CSV export, or persisted file.
- The HIBP integration transmits only a 5-character hash prefix, per the k-anonymity design published by Troy Hunt — never a full password or full hash.
- HTML report output is escaped before being written, as defense-in-depth against injection.
- The passphrase generator uses `secrets`, not `random` — the only choice safe for security-sensitive randomness.
- API CORS is wide open (`allow_origins=["*"]`) for local demo purposes only; restrict this before any real deployment.

## Possible extensions

- Automated browser tests for the web demo (Playwright/Selenium)
- Rate limiting on the API for safe public deployment
- Support for the full EFF long wordlist out of the box (currently ships with a smaller demo list — see `passphrase_generator.py` docstring)

## Author

Abdallah Alzghoul — Cybersecurity student, Hashemite University
[github.com/abdullah-alzghoul](https://github.com/abdullah-alzghoul)
# Password Strength Checker + Analyzer

![CI](https://github.com/abdullah-alzghoul/password-strength-checker/actions/workflows/ci.yml/badge.svg)

A CLI security tool that scores password strength using entropy analysis, weak-pattern detection, and real-world breach checking via the Have I Been Pwned API — built as a cybersecurity portfolio project.

## Features

- **Entropy-based scoring** — Shannon entropy from actual character-set diversity, not a naive length check
- **Pattern detection** — flags common passwords, sequential runs (`123456`, `abcdef`), keyboard walks (`qwerty`, `asdfgh`), repeated characters, and leetspeak substitutions (`p@ssw0rd` → `password`)
- **Effective entropy** — raw entropy is reduced by any detected weak pattern, so a long password isn't scored as strong just because it's long
- **Breach checking** — queries the Have I Been Pwned API using the **k-anonymity model**: only the first 5 characters of the password's SHA-1 hash ever leave the machine. The full password, and the full hash, are never transmitted
- **Compromised override** — a password found in a known breach is flagged `Compromised` regardless of its calculated entropy, in line with NIST SP 800-63B guidance. High entropy offers no protection once a password is in attacker wordlists
- **Interactive CLI** — built with [Rich](https://github.com/Textualize/rich): color-coded strength meter, clear warnings, loop-based session
- **JSON, HTML, and PDF reports** — every analysis can be exported for record-keeping or sharing

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

1. **`entropy.py`** calculates raw Shannon entropy (`length × log2(charset_size)`) and classifies it into a strength tier.
2. **`pattern_detector.py`** independently checks the password against a common-password wordlist (with leetspeak normalization), sequential runs, QWERTY keyboard walks, and repeated characters — each detected weakness carries an entropy penalty.
3. **`scorer.py`** combines both: `effective_entropy = raw_entropy − penalties`. If the password also matches a known breach, the result is overridden to `Compromised` outright, independent of the entropy math.
4. **`breach_checker.py`** implements the HIBP k-anonymity flow: hash the password with SHA-1, send only the 5-character prefix, and check the returned suffix list locally.
5. **`report_generator.py`** serializes the final result to JSON and a self-contained, styled HTML file (with HTML-escaped warning text to prevent injection if the wordlist source ever changes).

## Installation

```powershell
git clone https://github.com/abdullah-alzghoul/password-strength-checker.git
cd password-strength-checker
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
```

## Usage

```powershell
python -m src.cli
```

Enter a password when prompted. Results include length, raw and effective entropy, strength tier, a color-coded meter, and any detected warnings. You'll be offered the option to save the result as JSON + HTML after each check.

## Docker

```powershell
docker build -t password-checker .
docker run -it --rm password-checker

```text
password-checker/
├── src/
│   ├── core/
│   │   ├── entropy.py
│   │   ├── pattern_detector.py
│   │   ├── breach_checker.py
│   │   └── scorer.py
│   ├── cli.py
│   └── report_generator.py
├── tests/
│   ├── test_entropy.py
│   ├── test_pattern_detector.py
│   ├── test_breach_checker.py
│   ├── test_scorer.py
│   ├── test_cli.py
│   └── test_report_generator.py
├── data/
│   └── common_passwords.txt
├── requirements.txt
├── requirements-dev.txt
└── README.md
```

## Testing

65 unit and integration tests, including mocked network calls for the breach-checking module (no test hits the live API):

```powershell
python -m pytest tests/ -v
```

## Security notes

- No plaintext password is ever written to a log, report, or persisted file.
- The HIBP integration never transmits a full password or a full password hash — only a 5-character hash prefix, per the k-anonymity design published by Troy Hunt.
- HTML report output is escaped (`html.escape`) before being written, as defense-in-depth against injection if the wordlist source is ever swapped for an external one.

## Possible extensions

- Context-aware check (flag passwords containing the username/email)
- Local mutation-simulation against common password-cracking rule sets
- NIST / PCI-DSS / Active Directory compliance matrix
- FastAPI wrapper exposing the same core logic as a service

## Author

Abdallah Alzghoul — Cybersecurity student, Hashemite University
[github.com/abdullah-alzghoul](https://github.com/abdullah-alzghoul)
FROM python:3.14-slim

WORKDIR /app

# Runtime dependencies only — ruff/mypy/pytest ما إلهم داعي بالصورة النهائية
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ src/
COPY data/ data/

# تشغيل كـ non-root — ممارسة أمان أساسية
RUN useradd --create-home appuser
USER appuser

ENTRYPOINT ["python", "-m", "src.cli"]
FROM python:3.12-slim

WORKDIR /app

# Install dependencies first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy every application module explicitly — no ambiguity
COPY main.py       ./main.py
COPY transform.py  ./transform.py
COPY frameworks.py ./frameworks.py
COPY static/       ./static/

# Non-root user
RUN adduser --disabled-password --gecos "" appuser \
    && chown -R appuser /app
USER appuser

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

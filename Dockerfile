FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
RUN useradd -m app
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY tools ./tools
COPY lab ./lab
COPY web ./web
COPY vectors ./vectors
COPY docs ./docs
COPY scripts ./scripts
RUN pip install --no-cache-dir -e ".[qr]"
USER app
# Hugging Face Spaces uses 7860; Render/Koyeb inject $PORT.
ENV PORT=7860
EXPOSE 7860
CMD ["sh","-c","python tools/web_console.py --host 0.0.0.0 --port ${PORT} --mode demo"]

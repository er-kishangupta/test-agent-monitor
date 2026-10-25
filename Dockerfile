FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY static ./static
COPY config ./config
COPY runbooks ./runbooks
COPY data ./data
COPY scripts ./scripts
COPY tests ./tests
# run as an unprivileged user; /srv/out is the only writable location
RUN useradd --system --uid 10001 --no-create-home app && mkdir -p out && chown -R app:app /srv/out
USER app
EXPOSE 8000
# health check follows the scheme: HTTPS when a certificate is configured (loopback only, so the certificate name is not verified here)
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import os,ssl,urllib.request as u;t=os.environ.get('TLS_CERT_FILE');u.urlopen(('https' if t else 'http')+'://127.0.0.1:8000/healthz',context=ssl._create_unverified_context() if t else None)" || exit 1
# app.serve starts HTTPS when TLS_CERT_FILE and TLS_KEY_FILE are set and refuses to fall back to plain HTTP if they are set but missing
CMD ["python", "-m", "app.serve"]

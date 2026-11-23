FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates gosu tesseract-ocr tesseract-ocr-hin \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --home-dir /nonexistent --shell /usr/sbin/nologin app

COPY requirements.txt requirements-production.txt ./
RUN pip install --no-cache-dir --requirement requirements-production.txt

COPY --chown=app:app . /app
RUN chmod 0555 /app/docker-entrypoint.sh \
    && chmod -R a-w /app

EXPOSE 10000
ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["gunicorn", "--config", "gunicorn.conf.py", "wsgi:app"]

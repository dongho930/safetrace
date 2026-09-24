# 조사 Worker: Python 3.13 + Playwright Chromium(시스템 의존성 포함), 비관리자(pwuser) 실행.
# playwright 버전은 backend/requirements.lock 으로 고정된다.
FROM python:3.13.7-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
WORKDIR /src
COPY backend/pyproject.toml backend/requirements.lock ./
COPY backend/src ./src
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -c requirements.lock ".[browser]" \
 && python -m playwright install --with-deps chromium \
 && rm -rf /src /var/lib/apt/lists/* \
 && groupadd -r pwuser && useradd -r -g pwuser -m -d /home/pwuser -s /usr/sbin/nologin pwuser
USER pwuser
WORKDIR /home/pwuser

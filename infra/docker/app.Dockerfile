# api · signer · egress-proxy 공용 이미지(브라우저 없음). 버전·다이제스트 고정은 CI 에서 갱신한다.
FROM python:3.13.7-slim-bookworm AS build
WORKDIR /src
COPY backend/pyproject.toml backend/requirements.lock ./
COPY backend/src ./src
RUN pip install --no-cache-dir --upgrade pip \
 && pip wheel --no-cache-dir -c requirements.lock -w /wheels .

FROM python:3.13.7-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN groupadd -r app && useradd -r -g app -d /home/app -s /usr/sbin/nologin app \
 && mkdir -p /data /state && chown app:app /data /state
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir --no-index /wheels/*.whl && rm -rf /wheels
USER app
WORKDIR /home/app
EXPOSE 8000 8081 3128

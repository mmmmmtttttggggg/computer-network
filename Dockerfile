FROM python:3.12.8-slim-bookworm
WORKDIR /app
COPY requirements.lock pyproject.toml README.md ./
RUN python -m pip install --no-cache-dir -r requirements.lock
COPY src ./src
RUN python -m pip install --no-cache-dir --no-deps . && useradd -u 10001 -m netscope && mkdir /data && chown netscope:netscope /data
USER netscope
ENV NETSCOPE_DATA=/data
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "app.web.server:app_factory", "--factory", "--host", "0.0.0.0", "--port", "8000"]

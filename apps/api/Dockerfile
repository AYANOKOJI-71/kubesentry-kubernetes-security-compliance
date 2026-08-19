FROM python:3.12-slim

WORKDIR /workspace

COPY pyproject.toml ./
COPY apps/api/src ./apps/api/src
RUN pip install --no-cache-dir .

EXPOSE 4900

CMD ["uvicorn", "kubesentry.main:app", "--app-dir", "apps/api/src", "--host", "0.0.0.0", "--port", "4900"]

<<<<<<< HEAD
FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y gcc curl
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
=======
FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y gcc curl
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
>>>>>>> 71c662a9431a745ba0d782da0750690121796c37
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
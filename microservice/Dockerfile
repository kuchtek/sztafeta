FROM python:3.9-slim

WORKDIR /microservice

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create directory for SQLite database
RUN mkdir -p /microservice/data

# Copy only the necessary files
COPY data_collector.py .
COPY .env .

# Set environment variables
ENV PYTHONPATH=/microservice
ENV DB_TYPE=sqlite
ENV DATABASE_URL=sqlite:///data/running_stats.db

# Run the collector
CMD ["python", "data_collector.py"]
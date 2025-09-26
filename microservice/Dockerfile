FROM python:3.11-slim

WORKDIR /data_collector

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy only the necessary files
COPY data_collector.py .
# COPY .env .

# Set environment variables
ENV PYTHONPATH=/data_collector
ENV DB_TYPE=sqlite
ENV DATABASE_URL=sqlite:///data_collector/data/hejto_posts.db

# Run the collector
CMD ["python", "data_collector.py"]
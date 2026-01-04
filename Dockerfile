FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install mosquitto for mosquitto_ctrl command (includes the broker and utilities)
RUN apt-get update && \
    apt-get install -y --no-install-recommends mosquitto && \
    rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app ./app

# Expose port
EXPOSE 8000

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Run the application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

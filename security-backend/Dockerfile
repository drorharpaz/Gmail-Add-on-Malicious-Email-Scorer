# Use the official Python image as a base
FROM python:3.9-slim

# Set environment variables to ensure logs are sent to Cloud Run immediately
ENV PYTHONUNBUFFERED True

# Set the working directory inside the container
WORKDIR /app

# Copy the requirements file first to leverage Docker cache
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Use gunicorn as the production web server
# We bind it to the $PORT environment variable provided by Cloud Run
CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 0 main:app

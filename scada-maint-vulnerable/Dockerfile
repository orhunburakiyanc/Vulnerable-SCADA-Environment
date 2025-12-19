# Minimal, predictable Python image
FROM python:3.12-slim

# Prevents Python from writing .pyc files + makes logs show immediately
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install dependencies first (better Docker caching)
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy the project code (manage.py, scada_maint/, portal/, templates/, etc.)
COPY . /app

EXPOSE 8000

# Minimal: run Django dev server.
# We'll upgrade this later to use entrypoint.sh for migrations/seed automation.
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]

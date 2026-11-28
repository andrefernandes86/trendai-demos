FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py aws_lambda_wsgi.py ./
EXPOSE 5000
# Deliberately vulnerable demo API (SQLi / weak auth / XSS). Lab network only.
CMD ["gunicorn", "-b", "0.0.0.0:5000", "-w", "2", "app:app"]

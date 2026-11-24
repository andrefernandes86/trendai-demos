FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py tenants.py protection.py ./
COPY static ./static
# 8000 = operator control panel + app (internal, reached through the portal login)
# 8090 = public AI target (no login) for red-team tools such as Vantyr
EXPOSE 8000 8090
CMD ["python", "app.py"]

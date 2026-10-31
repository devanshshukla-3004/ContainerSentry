FROM python:latest
WORKDIR /app
ADD https://example.invalid/install.sh /tmp/install.sh
RUN chmod 777 /app
COPY . .
CMD ["python", "app.py"]

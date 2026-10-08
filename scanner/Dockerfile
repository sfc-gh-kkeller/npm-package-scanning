FROM node:22-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY scan.py entrypoint.sh /app/
RUN chmod +x /app/entrypoint.sh && useradd -m -u 1001 scanner
USER scanner
ENTRYPOINT ["/app/entrypoint.sh"]

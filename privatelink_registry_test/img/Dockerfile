FROM node:20-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && rm -rf /var/lib/apt/lists/*
COPY test.sh /test.sh
RUN chmod +x /test.sh
CMD ["/test.sh"]

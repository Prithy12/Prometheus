FROM minio/minio:latest

# Environment variables for MinIO
ENV MINIO_ROOT_USER=minioadmin
ENV MINIO_ROOT_PASSWORD=minioadmin
ENV MINIO_STORAGE_CLASS_STANDARD=EC:2
ENV MINIO_BROWSER=on
ENV MINIO_PROMETHEUS_AUTH_TYPE=public
ENV MINIO_REGION=us-east-1

# Volume for persisting data
VOLUME ["/data"]

# Create the evidence-vault bucket and set policies at startup
COPY setup.sh /setup.sh
RUN chmod +x /setup.sh

# Default bucket name for evidence storage
ENV MINIO_DEFAULT_BUCKETS=evidence-vault

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD curl -f http://localhost:9000/minio/health/ready || exit 1

# Expose MinIO ports
EXPOSE 9000 9001

# Set MinIO as entrypoint
ENTRYPOINT ["/usr/bin/docker-entrypoint.sh"]

# Command to run server and execute setup script
CMD ["minio", "server", "/data", "--console-address", ":9001"] 
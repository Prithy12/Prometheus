FROM postgres:13-alpine

# Environment variables for configuration
ENV POSTGRES_USER=netguardian
ENV POSTGRES_PASSWORD=netguardian_secure_password
ENV POSTGRES_DB=intelligence_db

# Copy schema.sql to docker-entrypoint-initdb.d, which will be executed on startup
COPY schema.sql /docker-entrypoint-initdb.d/

# Add health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD pg_isready -U $POSTGRES_USER -d $POSTGRES_DB || exit 1

# Expose PostgreSQL port
EXPOSE 5432

# Volume for persistent data storage
VOLUME /var/lib/postgresql/data 
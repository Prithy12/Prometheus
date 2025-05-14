FROM clickhouse/clickhouse-server:latest

# Copy configuration files
COPY config/config.xml /etc/clickhouse-server/config.d/
COPY config/users.xml /etc/clickhouse-server/users.d/

# Copy schema initialization script
COPY schema.sql /docker-entrypoint-initdb.d/
COPY init-db.sh /docker-entrypoint-initdb.d/

# Set permissions
RUN chmod 755 /docker-entrypoint-initdb.d/init-db.sh

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8123/ping || exit 1

EXPOSE 8123 9000

# Volume for persistent data storage
VOLUME /var/lib/clickhouse 
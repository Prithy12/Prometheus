#!/bin/bash
set -e

# Wait for ClickHouse server to start
until clickhouse-client --query "SELECT 1" ; do
  echo "Waiting for ClickHouse server to start..."
  sleep 1
done

echo "Initializing ClickHouse database..."

# Run schema.sql to create tables and views
clickhouse-client --multiquery < /docker-entrypoint-initdb.d/schema.sql

echo "ClickHouse database initialized successfully!" 
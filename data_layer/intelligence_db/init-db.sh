#!/bin/bash
set -e

# Generate self-signed SSL certificate
if [ ! -f "/var/lib/postgresql/server.crt" ]; then
  echo "Generating SSL certificate for PostgreSQL"
  cd /var/lib/postgresql
  openssl req -new -text -passout pass:abcd -subj /CN=localhost -out server.req -keyout privkey.pem
  openssl rsa -in privkey.pem -passin pass:abcd -out server.key
  chmod 600 server.key
  openssl req -x509 -in server.req -text -key server.key -out server.crt
  chown postgres:postgres server.key server.crt
  rm -f server.req privkey.pem
fi

# Copy configuration files
if [ -f "/tmp/pg_hba.conf" ]; then
  cp /tmp/pg_hba.conf /var/lib/postgresql/data/pg_hba.conf
  chown postgres:postgres /var/lib/postgresql/data/pg_hba.conf
  chmod 600 /var/lib/postgresql/data/pg_hba.conf
fi

if [ -f "/tmp/postgresql.conf" ]; then
  cp /tmp/postgresql.conf /var/lib/postgresql/data/postgresql.conf
  chown postgres:postgres /var/lib/postgresql/data/postgresql.conf
  chmod 600 /var/lib/postgresql/data/postgresql.conf
fi

echo "PostgreSQL initialization completed" 
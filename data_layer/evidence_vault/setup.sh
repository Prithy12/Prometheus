#!/bin/bash
set -e

# Wait for MinIO server to be ready
echo "Waiting for MinIO server to be ready..."
until curl -s http://localhost:9000/minio/health/live; do
  sleep 1
done

echo "MinIO is up and running"

# Create client configuration
mc alias set myminio http://localhost:9000 $MINIO_ROOT_USER $MINIO_ROOT_PASSWORD

# Create the evidence-vault bucket if it doesn't exist
if ! mc ls myminio/evidence-vault > /dev/null 2>&1; then
  echo "Creating evidence-vault bucket"
  mc mb myminio/evidence-vault
fi

# Enable versioning for compliance and audit requirements
echo "Enabling bucket versioning"
mc version enable myminio/evidence-vault

# Set encryption on the bucket
echo "Enabling bucket encryption"
mc encrypt set SSE-S3 myminio/evidence-vault

# Create encryption key for additional security
echo "Creating encryption key"
head -c 32 /dev/urandom > /tmp/enckey.key
mc admin kms key create myminio enckey.key /tmp/enckey.key
rm /tmp/enckey.key

# Set lifecycle policy to move data to reduced redundancy after 90 days
cat > /tmp/lifecycle.json << EOF
{
  "Rules": [
    {
      "Status": "Enabled",
      "ID": "Evidence-Lifecycle",
      "Filter": {
        "Prefix": ""
      },
      "Transitions": [
        {
          "Days": 90,
          "StorageClass": "REDUCED_REDUNDANCY"
        }
      ]
    }
  ]
}
EOF

mc ilm import myminio/evidence-vault < /tmp/lifecycle.json
rm /tmp/lifecycle.json

# Set a policy for the bucket to restrict access
cat > /tmp/policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"AWS": ["*"]},
      "Action": ["s3:GetBucketLocation"],
      "Resource": ["arn:aws:s3:::evidence-vault"]
    },
    {
      "Effect": "Allow",
      "Principal": {"AWS": ["*"]},
      "Action": [
        "s3:PutObject",
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::evidence-vault",
        "arn:aws:s3:::evidence-vault/*"
      ],
      "Condition": {
        "IpAddress": {
          "aws:SourceIp": [
            "127.0.0.1/32",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16"
          ]
        }
      }
    }
  ]
}
EOF

mc policy set-json /tmp/policy.json myminio/evidence-vault
rm /tmp/policy.json

echo "MinIO setup completed successfully" 
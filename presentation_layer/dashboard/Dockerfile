FROM nginx:alpine

WORKDIR /usr/share/nginx/html

# Copy the dashboard files to the container
COPY . /usr/share/nginx/html

# Copy nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Expose port 80
EXPOSE 80

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost/ || exit 1

# Run nginx in the foreground
CMD ["nginx", "-g", "daemon off;"] 
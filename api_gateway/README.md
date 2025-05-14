# NetGuardian API Gateway

The API Gateway for the NetGuardian security system. This gateway serves as the primary interface for external components to interact with the NetGuardian platform.

## Features

- RESTful API endpoints for:
  - Security events (CRUD + search/filter)
  - Threat intelligence (IOCs, threat actors, vulnerabilities)
  - Evidence management (upload, download, search)
- JWT Authentication and Role-Based Access Control
- Swagger/OpenAPI documentation
- Input validation and error handling
- Logging and monitoring
- Rate limiting and security headers

## Prerequisites

- Node.js 16.x or higher
- Docker (for containerized deployment)
- Access to NetGuardian Data Layer services

## Installation

### Local Development

1. Clone the repository:
   ```
   git clone https://github.com/your-organization/netguardian.git
   cd netguardian/github/prometheus/api_gateway
   ```

2. Install dependencies:
   ```
   npm install
   ```

3. Set up environment variables:
   ```
   cp .env.example .env
   ```
   Edit the `.env` file with your settings.

4. Generate Swagger documentation:
   ```
   npm run docs
   ```

5. Start the server:
   ```
   npm run dev
   ```

### Docker Deployment

1. Build the Docker image:
   ```
   docker build -t netguardian/api-gateway .
   ```

2. Run the container:
   ```
   docker run -p 5000:5000 --env-file .env netguardian/api-gateway
   ```

## API Documentation

API documentation is available at `/api-docs` when the server is running. The documentation is generated from JSDoc comments in the route files using Swagger/OpenAPI.

## Authentication

The API Gateway uses JWT (JSON Web Token) for authentication:

1. Obtain a token by calling `POST /api/auth/login` with valid credentials
2. Include the token in the `Authorization` header of subsequent requests:
   ```
   Authorization: Bearer <your-token>
   ```

### Default Users

For testing and development, the following users are available:

- Admin User:
  - Username: `admin`
  - Password: `admin123`
  - Role: `admin`

- Analyst User:
  - Username: `analyst`
  - Password: `analyst123`
  - Role: `analyst`

- Regular User:
  - Username: `user`
  - Password: `user123`
  - Role: `user`

## Testing

### Run All Tests

```
npm test
```

### Run Unit Tests

```
npm run test:unit
```

### Run Integration Tests

```
npm run test:integration
```

### Generate Test Coverage Report

```
npm run test:coverage
```

## Environment Variables

The following environment variables can be configured:

| Variable | Description | Default |
| --- | --- | --- |
| PORT | Port to run the server on | 5000 |
| NODE_ENV | Environment mode | development |
| LOG_LEVEL | Logging level | info |
| JWT_SECRET | Secret for JWT signing | netguardian-dev-secret |
| JWT_EXPIRES_IN | JWT expiration time | 24h |
| DATA_LAYER_API_URL | URL of the Data Layer API | http://data-layer-api:3000 |
| API_TIMEOUT | API request timeout (ms) | 5000 |

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contact

For issues and inquiries, please contact your NetGuardian system administrator. 
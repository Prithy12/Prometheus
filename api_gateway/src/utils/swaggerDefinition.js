/**
 * Swagger/OpenAPI definition for the API Gateway
 */
module.exports = {
  openapi: '3.0.0',
  info: {
    title: 'NetGuardian API Gateway',
    version: '1.0.0',
    description: 'API Gateway for the NetGuardian security system',
    license: {
      name: 'MIT',
    },
    contact: {
      name: 'NetGuardian Team',
    },
  },
  servers: [
    {
      url: '/api',
      description: 'API Gateway server',
    },
  ],
  components: {
    securitySchemes: {
      bearerAuth: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
      },
    },
    schemas: {
      Error: {
        type: 'object',
        properties: {
          status: {
            type: 'string',
            example: 'error',
          },
          message: {
            type: 'string',
            example: 'Error message',
          },
        },
      },
      SecurityEvent: {
        type: 'object',
        properties: {
          event_id: { type: 'string', format: 'uuid' },
          timestamp: { type: 'string', format: 'date-time' },
          source_ip: { type: 'string', format: 'ipv4' },
          source_port: { type: 'integer' },
          destination_ip: { type: 'string', format: 'ipv4' },
          destination_port: { type: 'integer' },
          protocol: { type: 'string' },
          event_type: { 
            type: 'string',
            enum: [
              'intrusion_attempt',
              'malware_detection',
              'reconnaissance',
              'data_exfiltration',
              'credential_access',
              'lateral_movement',
              'privilege_escalation',
              'persistence',
              'defense_evasion',
              'command_and_control',
              'impact',
              'other'
            ]
          },
          severity: { type: 'integer', minimum: 1, maximum: 10 },
          confidence: { type: 'integer', minimum: 1, maximum: 10 },
          description: { type: 'string' },
          raw_data: { type: 'string' },
          processed_by: { type: 'string' },
          network_segment: { type: 'string' },
          asset_id: { type: 'string' }
        },
        required: ['event_id', 'timestamp', 'event_type', 'severity']
      },
      IOC: {
        type: 'object',
        properties: {
          ioc_id: { type: 'string', format: 'uuid' },
          type: { 
            type: 'string',
            enum: ['ip', 'domain', 'url', 'file_hash', 'email', 'user_agent']
          },
          value: { type: 'string' },
          confidence: { type: 'integer', minimum: 0, maximum: 100 },
          severity: { type: 'integer', minimum: 0, maximum: 10 },
          first_seen: { type: 'string', format: 'date-time' },
          last_seen: { type: 'string', format: 'date-time' },
          expiration: { type: 'string', format: 'date-time' },
          tags: { type: 'array', items: { type: 'string' } },
          source: { type: 'string' },
          description: { type: 'string' },
          context: { type: 'object' }
        },
        required: ['ioc_id', 'type', 'value', 'confidence', 'severity']
      },
      Evidence: {
        type: 'object',
        properties: {
          evidenceId: { type: 'string', format: 'uuid' },
          timestamp: { type: 'string', format: 'date-time' },
          type: { 
            type: 'string',
            enum: ['pcap', 'log', 'memory_dump', 'disk_image', 'network_flow', 'screenshot', 'timeline', 'other']
          },
          caseId: { type: 'string' },
          source: { type: 'string' },
          description: { type: 'string' },
          tags: { type: 'array', items: { type: 'string' } },
          hash: { 
            type: 'object',
            properties: {
              sha256: { type: 'string' },
              md5: { type: 'string' }
            }
          },
          chainOfCustody: { 
            type: 'array',
            items: {
              type: 'object',
              properties: {
                timestamp: { type: 'string', format: 'date-time' },
                action: { type: 'string' },
                user: { type: 'string' },
                description: { type: 'string' },
                signature: { type: 'string' }
              }
            }
          }
        },
        required: ['evidenceId', 'timestamp', 'type', 'description']
      },
      User: {
        type: 'object',
        properties: {
          id: { type: 'string', format: 'uuid' },
          username: { type: 'string' },
          email: { type: 'string', format: 'email' },
          role: { 
            type: 'string',
            enum: ['admin', 'analyst', 'user']
          },
          created_at: { type: 'string', format: 'date-time' },
          last_login: { type: 'string', format: 'date-time' }
        },
        required: ['id', 'username', 'email', 'role']
      },
      AuthResponse: {
        type: 'object',
        properties: {
          token: { type: 'string' },
          expiresIn: { type: 'integer' },
          user: {
            $ref: '#/components/schemas/User'
          }
        }
      }
    }
  },
  security: [
    {
      bearerAuth: [],
    },
  ],
  paths: {} // Will be populated by route definitions
}; 
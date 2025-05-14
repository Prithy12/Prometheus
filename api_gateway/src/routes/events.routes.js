/**
 * Events routes
 */
const express = require('express');
const { body, param, query } = require('express-validator');
const { validate } = require('../middleware/validationMiddleware');
const { authenticate, authorize } = require('../middleware/authMiddleware');
const eventsController = require('../controllers/events.controller');

const router = express.Router();

// Apply authentication middleware to all routes
router.use(authenticate);

/**
 * @swagger
 * /events:
 *   get:
 *     summary: Get all events with optional filtering
 *     tags: [Events]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 100
 *         description: Maximum number of events to return
 *       - in: query
 *         name: offset
 *         schema:
 *           type: integer
 *           default: 0
 *         description: Number of events to skip
 *       - in: query
 *         name: event_type
 *         schema:
 *           type: string
 *           enum: [intrusion_attempt, malware_detection, reconnaissance, data_exfiltration, credential_access, lateral_movement, privilege_escalation, persistence, defense_evasion, command_and_control, impact, other]
 *         description: Filter by event type
 *       - in: query
 *         name: severity
 *         schema:
 *           type: integer
 *           minimum: 1
 *           maximum: 10
 *         description: Filter by minimum severity
 *       - in: query
 *         name: source_ip
 *         schema:
 *           type: string
 *         description: Filter by source IP address
 *     responses:
 *       200:
 *         description: A list of security events
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: success
 *                 count:
 *                   type: integer
 *                 data:
 *                   type: object
 *                   properties:
 *                     events:
 *                       type: array
 *                       items:
 *                         $ref: '#/components/schemas/SecurityEvent'
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
router.get(
  '/',
  validate([
    query('limit').optional().isInt({ min: 1, max: 1000 }).withMessage('Limit must be between 1 and 1000'),
    query('offset').optional().isInt({ min: 0 }).withMessage('Offset must be a non-negative integer'),
    query('severity').optional().isInt({ min: 1, max: 10 }).withMessage('Severity must be between 1 and 10')
  ]),
  eventsController.getEvents
);

/**
 * @swagger
 * /events/{id}:
 *   get:
 *     summary: Get a security event by ID
 *     tags: [Events]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *         description: Event ID
 *     responses:
 *       200:
 *         description: A security event
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: success
 *                 data:
 *                   type: object
 *                   properties:
 *                     event:
 *                       $ref: '#/components/schemas/SecurityEvent'
 *       404:
 *         description: Event not found
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
router.get(
  '/:id',
  validate([
    param('id').isUUID().withMessage('Event ID must be a valid UUID')
  ]),
  eventsController.getEventById
);

/**
 * @swagger
 * /events:
 *   post:
 *     summary: Create a new security event
 *     tags: [Events]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/SecurityEvent'
 *     responses:
 *       201:
 *         description: Event created successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: success
 *                 message:
 *                   type: string
 *                   example: Event created successfully
 *                 data:
 *                   type: object
 *                   properties:
 *                     event_id:
 *                       type: string
 *                       format: uuid
 *       400:
 *         description: Validation error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
router.post(
  '/',
  authorize(['admin', 'analyst']),
  validate([
    body('event_type')
      .isIn([
        'intrusion_attempt', 'malware_detection', 'reconnaissance', 'data_exfiltration',
        'credential_access', 'lateral_movement', 'privilege_escalation', 'persistence',
        'defense_evasion', 'command_and_control', 'impact', 'other'
      ])
      .withMessage('Invalid event type'),
    body('severity')
      .isInt({ min: 1, max: 10 })
      .withMessage('Severity must be between 1 and 10'),
    body('confidence')
      .optional()
      .isInt({ min: 1, max: 10 })
      .withMessage('Confidence must be between 1 and 10')
  ]),
  eventsController.createEvent
);

/**
 * @swagger
 * /events/batch:
 *   post:
 *     summary: Create multiple security events in batch
 *     tags: [Events]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: array
 *             items:
 *               $ref: '#/components/schemas/SecurityEvent'
 *     responses:
 *       201:
 *         description: Events created successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: success
 *                 message:
 *                   type: string
 *                   example: Events created successfully
 *                 data:
 *                   type: object
 *                   properties:
 *                     count:
 *                       type: integer
 *                     event_ids:
 *                       type: array
 *                       items:
 *                         type: string
 *                         format: uuid
 *       400:
 *         description: Validation error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
router.post(
  '/batch',
  authorize(['admin', 'analyst']),
  eventsController.createEvents
);

/**
 * @swagger
 * /events/alerts:
 *   get:
 *     summary: Get security alerts (high severity events)
 *     tags: [Events]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 100
 *         description: Maximum number of alerts to return
 *       - in: query
 *         name: offset
 *         schema:
 *           type: integer
 *           default: 0
 *         description: Number of alerts to skip
 *     responses:
 *       200:
 *         description: A list of security alerts
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: success
 *                 count:
 *                   type: integer
 *                 data:
 *                   type: object
 *                   properties:
 *                     alerts:
 *                       type: array
 *                       items:
 *                         $ref: '#/components/schemas/SecurityEvent'
 */
router.get('/alerts', eventsController.getAlerts);

/**
 * @swagger
 * /events/summary:
 *   get:
 *     summary: Get event summary statistics
 *     tags: [Events]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Event summary statistics
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: success
 *                 data:
 *                   type: object
 *                   properties:
 *                     summary:
 *                       type: array
 *                       items:
 *                         type: object
 */
router.get('/summary', eventsController.getEventSummary);

module.exports = router; 
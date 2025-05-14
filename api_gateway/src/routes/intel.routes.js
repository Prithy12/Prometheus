/**
 * Intelligence routes
 */
const express = require('express');
const { body, param, query } = require('express-validator');
const { validate } = require('../middleware/validationMiddleware');
const { authenticate, authorize } = require('../middleware/authMiddleware');
const intelController = require('../controllers/intel.controller');

const router = express.Router();

// Apply authentication middleware to all routes
router.use(authenticate);

/**
 * @swagger
 * /intel/iocs:
 *   get:
 *     summary: Get all IOCs with optional filtering
 *     tags: [Intelligence]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 100
 *         description: Maximum number of IOCs to return
 *       - in: query
 *         name: offset
 *         schema:
 *           type: integer
 *           default: 0
 *         description: Number of IOCs to skip
 *       - in: query
 *         name: type
 *         schema:
 *           type: string
 *           enum: [ip, domain, url, file_hash, email, user_agent]
 *         description: Filter by IOC type
 *       - in: query
 *         name: value
 *         schema:
 *           type: string
 *         description: Filter by IOC value (exact match)
 *       - in: query
 *         name: severity
 *         schema:
 *           type: integer
 *           minimum: 0
 *           maximum: 10
 *         description: Filter by minimum severity
 *     responses:
 *       200:
 *         description: A list of IOCs
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
 *                     iocs:
 *                       type: array
 *                       items:
 *                         $ref: '#/components/schemas/IOC'
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
router.get(
  '/iocs',
  validate([
    query('limit').optional().isInt({ min: 1, max: 1000 }).withMessage('Limit must be between 1 and 1000'),
    query('offset').optional().isInt({ min: 0 }).withMessage('Offset must be a non-negative integer'),
    query('severity').optional().isInt({ min: 0, max: 10 }).withMessage('Severity must be between 0 and 10'),
    query('type').optional().isIn(['ip', 'domain', 'url', 'file_hash', 'email', 'user_agent']).withMessage('Invalid IOC type')
  ]),
  intelController.getIOCs
);

/**
 * @swagger
 * /intel/iocs/{id}:
 *   get:
 *     summary: Get an IOC by ID
 *     tags: [Intelligence]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *         description: IOC ID
 *     responses:
 *       200:
 *         description: An IOC
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
 *                     ioc:
 *                       $ref: '#/components/schemas/IOC'
 *       404:
 *         description: IOC not found
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
router.get(
  '/iocs/:id',
  validate([
    param('id').isUUID().withMessage('IOC ID must be a valid UUID')
  ]),
  intelController.getIOCById
);

/**
 * @swagger
 * /intel/iocs:
 *   post:
 *     summary: Create a new IOC
 *     tags: [Intelligence]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/IOC'
 *     responses:
 *       201:
 *         description: IOC created successfully
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
 *                   example: IOC created successfully
 *                 data:
 *                   type: object
 *                   properties:
 *                     ioc:
 *                       $ref: '#/components/schemas/IOC'
 *       400:
 *         description: Validation error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
router.post(
  '/iocs',
  authorize(['admin', 'analyst']),
  validate([
    body('type')
      .isIn(['ip', 'domain', 'url', 'file_hash', 'email', 'user_agent'])
      .withMessage('Invalid IOC type'),
    body('value')
      .notEmpty()
      .withMessage('IOC value is required'),
    body('confidence')
      .isInt({ min: 0, max: 100 })
      .withMessage('Confidence must be between 0 and 100'),
    body('severity')
      .isInt({ min: 0, max: 10 })
      .withMessage('Severity must be between 0 and 10')
  ]),
  intelController.createIOC
);

/**
 * @swagger
 * /intel/check:
 *   get:
 *     summary: Check if an entity is an IOC
 *     tags: [Intelligence]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: type
 *         required: true
 *         schema:
 *           type: string
 *           enum: [ip, domain, url, file_hash, email, user_agent]
 *         description: IOC type
 *       - in: query
 *         name: value
 *         required: true
 *         schema:
 *           type: string
 *         description: Value to check
 *     responses:
 *       200:
 *         description: Check result
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
 *                     isIOC:
 *                       type: boolean
 *                     matches:
 *                       type: array
 *                       items:
 *                         $ref: '#/components/schemas/IOC'
 *       400:
 *         description: Validation error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
router.get(
  '/check',
  validate([
    query('type')
      .isIn(['ip', 'domain', 'url', 'file_hash', 'email', 'user_agent'])
      .withMessage('Invalid IOC type'),
    query('value')
      .notEmpty()
      .withMessage('Value is required')
  ]),
  intelController.checkIOC
);

module.exports = router; 
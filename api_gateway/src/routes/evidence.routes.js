/**
 * Evidence routes
 */
const express = require('express');
const { body, param, query } = require('express-validator');
const { validate } = require('../middleware/validationMiddleware');
const { authenticate, authorize } = require('../middleware/authMiddleware');
const evidenceController = require('../controllers/evidence.controller');

const router = express.Router();

// Apply authentication middleware to all routes
router.use(authenticate);

/**
 * @swagger
 * /evidence:
 *   post:
 *     summary: Upload evidence
 *     tags: [Evidence]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - data
 *               - metadata
 *             properties:
 *               data:
 *                 type: string
 *                 format: binary
 *                 description: Base64 encoded evidence data
 *               metadata:
 *                 type: object
 *                 required:
 *                   - type
 *                   - description
 *                 properties:
 *                   evidenceId:
 *                     type: string
 *                     format: uuid
 *                     description: Optional evidence ID (will be generated if not provided)
 *                   type:
 *                     type: string
 *                     enum: [pcap, log, memory_dump, disk_image, network_flow, screenshot, timeline, other]
 *                   caseId:
 *                     type: string
 *                   description:
 *                     type: string
 *                   source:
 *                     type: string
 *                   tags:
 *                     type: array
 *                     items:
 *                       type: string
 *     responses:
 *       201:
 *         description: Evidence uploaded successfully
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
 *                   example: Evidence uploaded successfully
 *                 data:
 *                   type: object
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
    body('data').notEmpty().withMessage('Evidence data is required'),
    body('metadata.type')
      .isIn(['pcap', 'log', 'memory_dump', 'disk_image', 'network_flow', 'screenshot', 'timeline', 'other'])
      .withMessage('Invalid evidence type'),
    body('metadata.description').notEmpty().withMessage('Evidence description is required')
  ]),
  evidenceController.uploadEvidence
);

/**
 * @swagger
 * /evidence/{id}:
 *   get:
 *     summary: Get evidence metadata
 *     tags: [Evidence]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *         description: Evidence ID
 *     responses:
 *       200:
 *         description: Evidence metadata
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
 *                     metadata:
 *                       $ref: '#/components/schemas/Evidence'
 *       404:
 *         description: Evidence not found
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
router.get(
  '/:id',
  validate([
    param('id').isUUID().withMessage('Evidence ID must be a valid UUID')
  ]),
  evidenceController.getEvidenceMetadata
);

/**
 * @swagger
 * /evidence/{id}/download:
 *   get:
 *     summary: Download evidence
 *     tags: [Evidence]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *         description: Evidence ID
 *     responses:
 *       200:
 *         description: Evidence data
 *         content:
 *           application/octet-stream:
 *             schema:
 *               type: string
 *               format: binary
 *       404:
 *         description: Evidence not found
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
router.get(
  '/:id/download',
  validate([
    param('id').isUUID().withMessage('Evidence ID must be a valid UUID')
  ]),
  evidenceController.downloadEvidence
);

/**
 * @swagger
 * /evidence/{id}/chain:
 *   get:
 *     summary: Get evidence chain of custody
 *     tags: [Evidence]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *         description: Evidence ID
 *     responses:
 *       200:
 *         description: Chain of custody
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
 *                     chain:
 *                       type: array
 *                       items:
 *                         type: object
 *                         properties:
 *                           timestamp:
 *                             type: string
 *                             format: date-time
 *                           action:
 *                             type: string
 *                           user:
 *                             type: string
 *                           description:
 *                             type: string
 *       404:
 *         description: Evidence not found
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
router.get(
  '/:id/chain',
  validate([
    param('id').isUUID().withMessage('Evidence ID must be a valid UUID')
  ]),
  evidenceController.getChainOfCustody
);

/**
 * @swagger
 * /evidence/search:
 *   get:
 *     summary: Search for evidence
 *     tags: [Evidence]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: type
 *         schema:
 *           type: string
 *           enum: [pcap, log, memory_dump, disk_image, network_flow, screenshot, timeline, other]
 *         description: Filter by evidence type
 *       - in: query
 *         name: caseId
 *         schema:
 *           type: string
 *         description: Filter by case ID
 *       - in: query
 *         name: tag
 *         schema:
 *           type: string
 *         description: Filter by tag
 *       - in: query
 *         name: startDate
 *         schema:
 *           type: string
 *           format: date-time
 *         description: Filter by start date
 *       - in: query
 *         name: endDate
 *         schema:
 *           type: string
 *           format: date-time
 *         description: Filter by end date
 *     responses:
 *       200:
 *         description: Search results
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
 *                     evidence:
 *                       type: array
 *                       items:
 *                         $ref: '#/components/schemas/Evidence'
 */
router.get('/search', evidenceController.searchEvidence);

module.exports = router; 
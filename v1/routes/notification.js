var express = require('express');
var router = express.Router();
    
const {
    getAllNotifications,
    readAllNotifications,
    getNotificationCount
 } = require('../controllers/notification.controller')

const authenticate = require('../../middleware/authenticate');

router.get('/get-all-notifications', authenticate, getAllNotifications);
router.get('/read-all-notifications', authenticate, readAllNotifications);
router.get('/get-notification-count', authenticate, getNotificationCount);

module.exports = router;

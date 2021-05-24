const mongoose = require('mongoose');
var Schema = mongoose.Schema;
const dateFormat = require('../helper/dateformat.helper');
const constants = require('../config/constants');

const notificationSchema = new mongoose.Schema({
    notification: {
        type: String,
        required: true
    },
    user_id: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: 'users'
    },
    is_read: {
        type: Number,
        default: constants.NOTIFICATION_READ.UNREAD
    },
    notification_type: {
        type: String,
        required: true
    },
    notification_image: {
        type: String,
        required: true
    },
    created_at: {
        type: Number,
        default: dateFormat.set_current_timestamp()
    },
    sync_at: {
        type: Number
    },
    deleted_at: {
        type: Number,
        default: null,
    }
});


notificationSchema.index({
    "user_id": 1,
    "created_at": 1
});

const notifications = mongoose.model('notifications', notificationSchema);
module.exports = notifications;

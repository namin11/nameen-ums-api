const {
    sendResponse
} = require('../../services/common.service')
const constants = require('../../config/constants')

const Notification = require('../../models/notification.model');

exports.getAllNotifications = async (req, res) => {
    try {

        let field, value;

        if (req.query.sortBy) {
            const parts = req.query.sortBy.split(':');
            field = parts[0];
            parts[1] === 'desc' ? value = -1 : value = 1;
        } else {
            field = "created_at",
                value = -1;
        }

        let limit = +req.query.limit || constants.LIMIT;
        let page = +req.query.page || constants.PAGE;

        let total = await Notification.countDocuments({
            _userId: req.user._id
        });
        let notificationsData = await Notification.find({
                user_id: req.user._id
            })
            .sort({
                [field]: value
            })
            .skip((page - 1) * limit)
            .limit(limit)
            .collation({
                locale: "en"
            });

        // for (let i = 0; i < notifications.length; i++) {
        //     // notifications[i].notificationImage = await commonFunction.getNotificationPicUrl(req, notifications[i].notificationImage)
        //     await commonFunction.generateAWSNotificationImageURL(notifications[i]);

        //     let status = notifications[i].notificationType;

        //     if(status != constants.NOTIFICATION.TRIVIA.TRIVIA_BROADCAST_MESSAGE && status != constants.NOTIFICATION.DFS.DFS_BROADCAST_MESSAGE && status != constants.NOTIFICATION.LEAGUE.LEAGUE_BROADCAST_MESSAGE){
        //         if(notifications[i].keys){

        //             let keyMessage = Lang.pushResponseIn(notifications[i].notification, req.headers.lang);
        //             let message = await commonFunction.replaceStringWithObjectData(keyMessage, notifications[i].keys);
        //             notifications[i].notification = message
        //         }
        //     }
        // }

        let data = {
            workout: notificationsData,
            limit: limit,
            page: page,
            total: total
        }

        return sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'NOTIFICATION.notification_fetch_success', data, req.headers.lang);

    } catch (err) {
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang);
    }
}

exports.readAllNotifications = async (req, res) => {
    try {

        let notifications = await Notification.updateMany({
            _userId: req.user._id
        }, {
            $set: {
                isRead: constants.NOTIFICATION_READ.READ
            }
        });
        return sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'NOTIFICATION.notification_read_success', data, req.headers.lang);

    } catch (err) {
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang);
    }
}


exports.getNotificationCount = async (req, res) => {
    try {

        let notificationCount = await Notification.countDocuments({
            _userId: req.user._id,
            isRead: constants.NOTIFICATION_READ.UNREAD
        });
        return sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'NOTIFICATION.notification_count_success', notificationCount, req.headers.lang);

    } catch (err) {
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang);
    }
}
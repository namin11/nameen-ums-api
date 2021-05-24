const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const { sendResponse } = require('../../services/common.service')
const dateFormat = require('../../helper/dateformat.helper');
const commanMessage = require('../../lang/en/message')
const constants = require('../../config/constants');
const ContactUs = require('../../models/contactUs.model');


const sendEmail = require('../../services/email.service');
const closeContactRequestTemplate = require('../services/emailTemplate/closeContactRequestTemplate');
const contactRequestTemplate = require('../services/emailTemplate/contactRequestTemplate');

exports.contactUs = async (req, res) => {
    const contactUs = new ContactUs(req.body)

    try {
        contactUs.created_at = await dateFormat.set_current_timestamp();
        contactUs.updated_at = await dateFormat.set_current_timestamp();

        await contactUs.save()


        await sendEmail(contactUs.email, commanMessage.ADMIN.contact_req_mail_subject, contactRequestTemplate({ email: contactUs.email, username: contactUs.username, subject: contactUs.subject, query: contactUs.query }));

        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'ADMIN.send_contact_request_success', {}, req.headers.lang);
    } catch (err) {
        console.log("err........", err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}

exports.getContactUsReq = async (req, res) => {
    try {
        const pageOptions = {
            page: parseInt(req.query.page),
            limit: parseInt(constants.PAGE_DATA_LIMIT)
        }

        var query = {};

        if (req.query.status) {
            query.$and = [
                { 'status': req.query.status },
            ]
        }

        if (req.query.sortBy) {
            const parts = req.query.sortBy.split(':');
            field = parts[0];
            parts[1] === 'desc' ? value = -1 : value = 1;
        }
        else {
            field = "created_at",
                value = 1;
        }

        const reqTotal = await ContactUs.countDocuments(query)

        // if (reqTotal.length == 0) {
        //     return sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'ADMIN.contactus_req_empty', {}, req.headers.lang);
        // }

        const contactReq = await ContactUs.find(query)
            .sort({ [field]: value })
            .skip((pageOptions.page - 1) * pageOptions.limit).limit(pageOptions.limit)

        let data = {}
        data.contact_request = contactReq;
        data.total = reqTotal;
        data.per_page = pageOptions.limit;
        data.current_page = pageOptions.page;

        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'ADMIN.get_contactus_req', data, req.headers.lang);
    } catch (err) {
        console.log("err........", err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}

exports.getRequestDetail = async (req, res) => {
    const _id = req.params.contactUsId

    try {
        const reqData = await ContactUs.findById(_id)

        if (!reqData) {
            sendResponse(res, constants.WEB_STATUS_CODE.NOT_FOUND, constants.STATUS_CODE.NOT_FOUND, 'GENERAL.general_error_content', {}, req.headers.lang);
        }

        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'ADMIN.get_contactus_req', reqData, req.headers.lang);
    } catch (err) {
        console.log("err........", err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}

exports.closeContactRequest = async (req, res) => {
    try {
        const _id = req.params.contactUsId
        const contactUsModel = await ContactUs.findById(_id)

        if (!contactUsModel) {
            return sendResponse(res, constants.WEB_STATUS_CODE.NOT_FOUND, constants.STATUS_CODE.NOT_FOUND, 'GENERAL.general_error_content', {}, req.headers.lang);
        }
        if (contactUsModel.status == 0) {
            return sendResponse(res, constants.WEB_STATUS_CODE.NOT_FOUND, constants.STATUS_CODE.NOT_FOUND, 'ADMIN.close_contact_request_already_closed', {}, req.headers.lang);
        }

        contactUsModel.status = 0
        await contactUsModel.save()

        await sendEmail(contactUsModel.email, commanMessage.ADMIN.contact_close_req_mail_subject, closeContactRequestTemplate({ username: contactUsModel.username, subject: contactUsModel.subject, query: contactUsModel.query }));

        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'ADMIN.close_contact_request_success', contactUsModel, req.headers.lang);
    } catch (err) {
        console.log("err........", err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}
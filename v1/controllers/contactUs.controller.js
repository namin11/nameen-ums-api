const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const { sendResponse } = require('../../services/common.service')
const dateFormat = require('../../helper/dateformat.helper');
// const commanMessage = require('../../helper/commonMessage')
const constants = require('../../config/constants');
const ContactUs = require('../../models/contactUs.model');
const User = require('../../models/user.model');

const sendEmail = require('../../services/email.service');
// const contactRequestTemplate = require('../services/emailTemplate/contactRequestTemplate');

// exports.contactUs = async (req, res) => {
//     const contactUs = new ContactUs(req.body)

//     try {
//         contactUs.created_at = await dateFormat.set_current_timestamp();
//         contactUs.updated_at = await dateFormat.set_current_timestamp();

//         await contactUs.save()

//         await sendEmail(contactUs.email, commanMessage.ADMIN.contact_req_mail_subject, contactRequestTemplate({ email: contactUs.email, username: contactUs.username, subject: contactUs.subject, query: contactUs.query }));

//         sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'ADMIN.send_contact_request_success', {}, req.headers.lang);
//     } catch (err) {
//         console.log("err........", err)
//         sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
//     }
// }

exports.getContactUsReq = async (req, res) => {
    try {


        let {
            tag_id,
            is_star,
            limit,
            page,
            status,
            skill_level,
            sortBy,
            q
        } = req.query

        limit = +limit || constants.LIMIT;
        page = +page || constants.PAGE;

        var query = {};

        if (status) {
            query.$and = [
                { 'status': req.query.status },
            ]
        }

        if (sortBy) {
            const parts = sortBy.split(':');
            field = parts[0];
            parts[1] === 'desc' ? value = -1 : value = 1;
        }
        else {
            field = "created_at",
                value = 1;
        }

        const search = q ? q : ''; // for searching

        if (search) {
            query.$or = [
                { 'username': new RegExp(search, 'i') },
                { 'email': new RegExp(search, 'i') },
                { 'query': new RegExp(search, 'i') }
            ]
        }

        console.log("pageOptions...",limit)
        console.log("..",page)

        const reqTotal = await ContactUs.countDocuments(query)
        const contactReq = await ContactUs.find(query)
            .sort({ [field]: value })
            .skip((page - 1) * limit).limit(limit)

        let data = {}

        data.contact_request = contactReq;
        data.total = reqTotal;
        data.limit = limit;
        data.page = page;

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
           return sendResponse(res, constants.WEB_STATUS_CODE.NOT_FOUND, constants.STATUS_CODE.NOT_FOUND, 'GENERAL.general_error_content', {}, req.headers.lang);
        }

        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'ADMIN.get_contactus_req', reqData, req.headers.lang);
    } catch (err) {
        console.log("err........", err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}
exports.deleteContactUs = async (req, res) => {
    try{
        let _id = req.params.contactUsId
        let deleteContactUs = await ContactUs.findByIdAndDelete(_id)
        if(deleteContactUs){
                let message = 'Query Deleted Successfully'
                return sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'ADMIN.close_contact_request_success', {}, req.headers.lang);
                } else {
                    return sendResponse(res, constants.WEB_STATUS_CODE.BAD_REQUEST, constants.STATUS_CODE.FAIL, 'Query not deleted', {}, req.headers.lang);
                }
    } catch (err) {
        console.log("err........", err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'Something went wrong', err.message, req.headers.lang)
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
        contactUsModel.closed_at = await dateFormat.set_current_timestamp();
        contactUsModel.updated_at = await dateFormat.set_current_timestamp();
        await contactUsModel.save()

        console.log("reqBody.email...",contactUsModel.email)

        let sendMailUser = {
            'to': contactUsModel.email,
            'templateSlug': constants.EMAIL_TEMPLATE.CONTACTUS_QUERY_CLOSED_USER,
            'data': {
                query: contactUsModel.query,
                username: contactUsModel.username
            }
        }

        let isSendEmailUser = await sendEmail(req, sendMailUser);
        if (isSendEmailUser) {
            console.log('email has been user sent');
        } else {
            console.log('email has not been sent');
        }

        
        let allAdmin = await User.find({ user_type: 1}).select('email').lean()
        
        allAdminEmail = allAdmin.map(e => e.email)
        console.log("allAdminEmail....",allAdminEmail)


        let sendMailAdmin = {
            'to': allAdminEmail,
            'templateSlug': constants.EMAIL_TEMPLATE.CONTACTUS_QUERY_CLOSED_ADMIN,
            'data': {
                query: contactUsModel.query,
                username: contactUsModel.username
            }
        }

        let isSendEmailAdmin = await sendEmail(req, sendMailAdmin);
        if (isSendEmailAdmin) {
            console.log('email has been admin sent');
        } else {
            console.log('email has not been sent');
        }


        // await sendEmail(contactUsModel.email, commanMessage.ADMIN.contact_close_req_mail_subject, closeContactRequestTemplate({ username: contactUsModel.username, subject: contactUsModel.subject, query: contactUsModel.query }));

        return sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'ADMIN.close_contact_request_success', contactUsModel, req.headers.lang);
    } catch (err) {
        console.log("err........", err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}
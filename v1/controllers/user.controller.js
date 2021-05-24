const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const {
    check,
    validationResult,
    query
} = require('express-validator');
const {
    responseMessage,
    sendResponse
} = require('../../services/common.service')
const dateFormat = require('../../helper/dateformat.helper');
const User = require('../../models/user.model')
const Course = require('../../models/course.model')
const Programs = require('../../models/programs.model')
const Fees = require('../../models/fees.model')
const Admin = require('../../models/admin.model')

const CourseFaculty = require('../../models/courseFaculty.model')
const CourseStudent = require('../../models/courseStudent.model')

const AttendanceStudent = require('../../models/attendanceStudent.model')
const AttendanceFaculty = require('../../models/attendanceFaculty.model')

const ContactUs = require('../../models/contactUs.model')
const Assignment = require('../../models/assignment.model')
const AssignmentStudent = require('../../models/assignmentStudent')
const Announcement = require('../../models/announcement.model')
const ExamSeating = require('../../models/examSeating.model')

const {
    isValid
} = require('../../services/blackListMail')

const {
    getUser,
    getUserDetails,
    Usersave,
    userVerifyToken,
    userVerifyEmail,
    updateUser,
    updateUserById,
    deleteUser

} = require('../services/user.service');

const sendEmail = require('../../services/email.service');
const Keys = require('../../keys/keys')
const constants = require('../../config/constants')
const {
    JWT_SECRET
} = require('../../keys/keys');
const {
    constant
} = require('lodash');


exports.logout = async (req, res, next) => {
    try {
        const reqBody = req.user
        let UserData = await User.findById(reqBody._id)
        UserData.tokens = null

        await UserData.save()
        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.logout_success', {}, req.headers.lang);

    } catch (err) {
        console.log(err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}

exports.login = async (req, res, next) => {
    try {
        const reqBody = req.body
        console.log("reqBody...", reqBody)
        let user = await User.findByCredentials(reqBody.register_id, reqBody.password);

        console.log("user....", user)

        if (user == 1) return sendResponse(res, constants.WEB_STATUS_CODE.BAD_REQUEST, constants.STATUS_CODE.FAIL, 'USER.email_not_found', {}, req.headers.lang);
        if (user == 2) return sendResponse(res, constants.WEB_STATUS_CODE.BAD_REQUEST, constants.STATUS_CODE.FAIL, 'USER.invalid_password', {}, req.headers.lang);

        if (user.verify_token == false) return sendResponse(res, constants.WEB_STATUS_CODE.BAD_REQUEST, constants.STATUS_CODE.FAIL, 'USER.not_verify_account', {}, req.headers.lang);
        if (user.status == 0) return sendResponse(res, constants.WEB_STATUS_CODE.BAD_REQUEST, constants.STATUS_CODE.FAIL, 'USER.inactive_account', {}, req.headers.lang);
        if (user.status == 2) return sendResponse(res, constants.WEB_STATUS_CODE.BAD_REQUEST, constants.STATUS_CODE.FAIL, 'USER.deactive_account', {}, req.headers.lang);
        if (user.deleted_at != null) return sendResponse(res, constants.WEB_STATUS_CODE.BAD_REQUEST, constants.STATUS_CODE.FAIL, 'USER.inactive_account', {}, req.headers.lang);

        let newToken = await user.generateAuthToken();

        console.log("user....", user)

        await user.save()

        let resData = user
        resData.tokens = '';


        delete resData.reset_password_token;
        delete resData.reset_password_expires;
        delete resData.password;
        resData.tokens = newToken

        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.login_success', resData, req.headers.lang);

    } catch (err) {
        console.log('err.....', err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}
exports.accountVerify = async (req, res, next) => {
    try {
        let message
        const userId = req.query.user_id
        const emailVerificationToken = req.query.emailVerificationToken
        const data = await userVerifyToken(userId, emailVerificationToken)
        if (data == 1) {
            res.redirect(Keys.BASEURL + `v1/users/email-verify/verify?user_id=${userId}`)
        } else {
            res.redirect(Keys.BASEURL + `v1/users/email-verify/unverify?user_id=${userId}`)
        }
    } catch (err) {
        console.log(err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}

exports.emailVerifyPage = async (req, res, next) => {
    try {
        let message, messageEng
        const status = req.params.status
        if (status == 'verify') {
            messageEng = responseMessage('USER.account_verify_success');
            console.log("messageEng..", messageEng)

            message = req.flash(
                'success',
                messageEng
            );
        } else {
            messageEng = responseMessage('USER.account_verify_fail');
            message = req.flash(
                'error',
                messageEng
            );
        }

        return res.render('message', {
            req: req,
            logoUrl: Keys.BASEURL + `images/logo/logo.png`,
            appBaseUrl: Keys.BASEURL,
            constants: constants,
            message: 'message',
            error: req.flash('error'),
            success: req.flash('success'),
        });
    } catch (err) {
        console.log(err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}


exports.emailVerify = async (req, res, next) => {
    try {
        const userId = req.query.user_id
        const emailVerificationToken = req.query.emailVerificationToken
        const email = req.query.email

        const data = await userVerifyEmail(userId, emailVerificationToken, email)
        if (data == 1) {
            message = req.flash(
                'success',
                `Your email has been verified successfully.`
            );

            return res.render('message', {
                req: req,
                logoUrl: Keys.BASEURL + `images/logo/logo.png`,
                appBaseUrl: Keys.BASEURL,
                constants: constants,
                message: 'message',
                error: req.flash('error'),
                success: req.flash('success'),
            });
        } else {
            message = req.flash(
                'error',
                'Your account verify link expire or invalid'
            );

            return res.render('message', {
                req: req,
                logoUrl: Keys.BASEURL + `images/logo/logo.png`,
                appBaseUrl: Keys.BASEURL,
                constants: constants,
                message: 'message',
                error: req.flash('error'),
                success: req.flash('success'),
            });
            // sendResponse(res, constants.WEB_STATUS_CODE.BAD_REQUEST, constants.STATUS_CODE.FAIL, 'USER.account_verify_fail', data, req.headers.lang);
        }
    } catch (err) {
        console.log(err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}


exports.forgotPassword = async (req, res, next) => {
    try {

        const reqBody = req.body
        let existingUser = await getUser(reqBody.email, 'email');

        if (!existingUser) {
            return sendResponse(res, constants.WEB_STATUS_CODE.NOT_FOUND, constants.STATUS_CODE.NOT_FOUND, 'USER.email_not_found', {}, req.headers.lang);
        }

        let updated_at = await dateFormat.set_current_timestamp();
        reset_password_token = await jwt.sign({
            data: reqBody.email
        }, JWT_SECRET, {
            expiresIn: constants.URL_EXPIRE_TIME
        })

        // let tempTokens = Math.floor(Math.random() * 10000000)
        let updateData = {
            updated_at: updated_at,
            reset_password_token: reset_password_token
        }


        let conditionData = {
            email: reqBody.email
        }

        const user = await updateUser(conditionData, updateData);

        let sendMail = {
            'to': reqBody.email,
            'templateSlug': constants.EMAIL_TEMPLATE.PASSWORD_RESET,
            'data': {
                userName: existingUser.first_name,
                url: Keys.BASEURL + 'v1/web/reset-password?token=' + reset_password_token
            }
        }

        let isSendEmail = await sendEmail(req, sendMail);
        if (isSendEmail) {
            console.log('email has been sent');
        } else {
            console.log('email has not been sent');
        }

        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.forgotPassword_email_success', user, req.headers.lang);

    } catch (err) {
        console.log(err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}


exports.changePassword = async (req, res, next) => {
    try {

        const reqBody = req.body


        if (reqBody.new_password !== reqBody.confirm_password) return sendResponse(res, constants.WEB_STATUS_CODE.BAD_REQUEST, constants.STATUS_CODE.FAIL, 'USER.password_mismatch', {}, req.headers.lang)

        let userDetails = await getUser(req.user._id);

        if (!userDetails.validPassword(reqBody.old_password)) return sendResponse(res, constants.WEB_STATUS_CODE.BAD_REQUEST, constants.STATUS_CODE.FAIL, 'USER.invalidOldPassword', {}, req.headers.lang)

        userDetails.password = await bcrypt.hash(reqBody.new_password, 10);
        userDetails.updated_at = await dateFormat.set_current_timestamp();

        const changePassword = updateUser({
            _id: userDetails._id
        }, userDetails)

        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.passwordUpdate_success', changePassword, req.headers.lang);

    } catch (err) {
        console.log(err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}


exports.resetPassword = async (req, res, next) => {
    try {

        const reqBody = req.body

        if (reqBody.new_password !== reqBody.confirm_password) {

            message = req.flash(
                'error',
                'New password and confirm password not matched.'
            );

            return res.redirect(
                Keys.BASEURL + 'v1/web/reset-password?token=' + reqBody.reset_password_token
            );
        }


        let userDetails = await getUser(reqBody.reset_password_token, "reset_password_token");

        if (!userDetails) {
            message = req.flash(
                'error',
                'Your account verify link expire or invalid.'
            );

            return res.render('message', {
                req: req,
                logoUrl: Keys.BASEURL + `images/logo/logo.png`,
                appBaseUrl: Keys.BASEURL,
                constants: constants,
                message: 'message',
                error: req.flash('error'),
                success: req.flash('success'),
            });
        }

        userDetails.password = await bcrypt.hash(reqBody.new_password, 10);
        userDetails.updated_at = await dateFormat.set_current_timestamp();
        userDetails.reset_password_token = null

        const changePassword = updateUser({
            reset_password_token: reqBody.reset_password_token
        }, userDetails)

        // sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.passwordUpdate_success', changePassword, req.headers.lang);

        message = req.flash(
            'success',
            'Your password successfully changed.'
        );

        return res.render('message', {
            req: req,
            logoUrl: Keys.BASEURL + `images/logo/logo.png`,
            appBaseUrl: Keys.BASEURL,
            constants: constants,
            message: 'message',
            error: req.flash('error'),
            success: req.flash('success'),
        });

    } catch (err) {
        console.log(err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}



exports.getProfile = async (req, res, next) => {
    try {
        let resData = req.user

        delete resData.password;
        delete resData.tokens;

        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.get_user_profile', resData, req.headers.lang);

    } catch (err) {
        console.log(err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}

exports.editProfile = async (req, res, next) => {
    try {
        const reqBody = req.body
        console.log("reqBody......", reqBody)

        reqBody.updated_at = await dateFormat.set_current_timestamp();

        const updateUserData = await updateUser({
            _id: req.user._id
        }, reqBody)

        let user = await User.findById(req.user._id).lean()
        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.profile_update_success', user, req.headers.lang);

    } catch (err) {
        console.log(err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}

exports.editUserProfile = async (req, res, next) => {
    try {
        const reqBody = req.body
        console.log("reqBody......", reqBody)

        let user = await User.findById(reqBody._id)

        reqBody.updated_at = await dateFormat.set_current_timestamp();

        await User.findByIdAndUpdate({
            _id: reqBody._id
        }, reqBody)

        let userData = await User.findById(reqBody._id).lean()
        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.profile_update_success', userData, req.headers.lang);

    } catch (err) {
        console.log(err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}

exports.viewDetails = async (req, res, next) => {
    try {
        let userId = req.params.user_id
        let userDetails = await User.findById(userId).lean()

        delete userDetails.password;
        delete userDetails.tokens;

        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.get_user_profile', userDetails, req.headers.lang);

    } catch (err) {
        console.log(err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}
exports.editContactUs = async (req, res) => {
    try {
        const reqBody = req.body

        const contactUs = await ContactUs.findByIdAndUpdate(reqBody._id, reqBody);

        console.log("reqBody.email...", contactUs)

        // await sendEmail(contactUs.email, commanMessage.ADMIN.contact_req_mail_subject, contactRequestTemplate({ email: contactUs.email, username: contactUs.username, subject: contactUs.subject, query: contactUs.query }));

        sendResponse(res, constants.WEB_STATUS_CODE.CREATED, constants.STATUS_CODE.SUCCESS, 'CONTACTUS.query_created_success', contactUs, req.headers.lang);
    } catch (err) {
        console.log("err........", err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}
exports.contactUs = async (req, res) => {
    try {
        const reqBody = req.body

        const contactUs = new ContactUs(reqBody)
        contactUs.created_at = await dateFormat.set_current_timestamp();
        contactUs.updated_at = await dateFormat.set_current_timestamp();
        contactUs.user_id = req.user._id

        let data = await contactUs.save()

        console.log("reqBody.email...", reqBody.email)

        let sendMailUser = {
            'to': reqBody.email,
            'templateSlug': constants.EMAIL_TEMPLATE.CONTACTUS_QUERY_CREATE_USER,
            'data': {
                query: reqBody.query,
                username: reqBody.username
            }
        }

        let isSendEmailUser = await sendEmail(req, sendMailUser);
        if (isSendEmailUser) {
            console.log('email has been user sent');
        } else {
            console.log('email has not been sent');
        }


        let allAdmin = await User.find({
            user_type: 1
        }).select('email').lean()

        allAdminEmail = allAdmin.map(e => e.email)
        console.log("allAdminEmail....", allAdminEmail)


        let sendMailAdmin = {
            'to': allAdminEmail,
            'templateSlug': constants.EMAIL_TEMPLATE.CONTACTUS_QUERY_CREATE_ADMIN,
            'data': {
                query: reqBody.query,
                username: reqBody.username
            }
        }

        let isSendEmailAdmin = await sendEmail(req, sendMailAdmin);
        if (isSendEmailAdmin) {
            console.log('email has been admin sent');
        } else {
            console.log('email has not been sent');
        }

        // await sendEmail(contactUs.email, commanMessage.ADMIN.contact_req_mail_subject, contactRequestTemplate({ email: contactUs.email, username: contactUs.username, subject: contactUs.subject, query: contactUs.query }));

        sendResponse(res, constants.WEB_STATUS_CODE.CREATED, constants.STATUS_CODE.SUCCESS, 'CONTACTUS.query_created_success', data, req.headers.lang);
    } catch (err) {
        console.log("err........", err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}


exports.notificationSettings = async (req, res, next) => {
    try {
        const userNotification = req.user.notification_settings
        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.get_user_notificatuon_setting', userNotification, req.headers.lang);

    } catch (err) {
        console.log(err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}


exports.userSocialLogin = async (req, res, next) => {
    try {

        let reqBody = req.body
        reqBody.device_type = (reqBody.device_type) ? reqBody.device_type : null
        reqBody.device_token = (reqBody.device_token) ? reqBody.device_token : null

        let user = await User.findOne({
            social_id: reqBody.social_id,
            social_type: reqBody.social_type
        });
        let userRegister

        if (!user) {

            if (reqBody.email) {
                const checkMail = await isValid(reqBody.email)
                if (checkMail == false) return sendResponse(res, constants.WEB_STATUS_CODE.BAD_REQUEST, constants.STATUS_CODE.FAIL, 'GENERAL.blackList_mail', {}, req.headers.lang);

            }
            let existingUser = await getUser(reqBody.email, 'email');

            if (existingUser) {
                console.log("heyy")
                existingUser.social_id = reqBody.social_id
                existingUser.social_type = reqBody.social_type
                existingUser = await dateFormat.set_current_timestamp();

                user = await existingUser.save()
            } else {
                reqBody.verify_token = true
                reqBody.updated_at = await dateFormat.set_current_timestamp()
                reqBody.created_at = await dateFormat.set_current_timestamp()
                user = await Usersave(reqBody);
                userRegister = true
            }
        } else {

            user.device_type = (reqBody.device_type) ? reqBody.device_type : null
            user.device_token = (reqBody.device_token) ? reqBody.device_token : null
            await user.save()
        }

        console.log("user...", user)

        if (user.status == 0) return sendResponse(res, constants.WEB_STATUS_CODE.BAD_REQUEST, constants.STATUS_CODE.FAIL, 'USER.inactive_account', {}, req.headers.lang);
        if (user.status == 2) return sendResponse(res, constants.WEB_STATUS_CODE.BAD_REQUEST, constants.STATUS_CODE.FAIL, 'USER.deactive_account', {}, req.headers.lang);
        if (user.deleted_at != null) return sendResponse(res, constants.WEB_STATUS_CODE.BAD_REQUEST, constants.STATUS_CODE.FAIL, 'USER.inactive_account', {}, req.headers.lang);

        let newToken = await user.generateAuthToken();

        let resData = user

        delete resData.reset_password_token;
        delete resData.reset_password_expires;
        delete resData.password;
        resData.tokens = newToken

        resData.height = resData.height == null ? resData.height : (resData.height).toFixed(2)
        resData.weight = resData.weight == null ? resData.weight : (resData.weight).toFixed(2)

        resData.userRegister = userRegister == true ? true : false

        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.social_login_success', resData, req.headers.lang, req.headers.lang);

    } catch (err) {
        console.log(err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}




exports.resendMail = async (req, res, next) => {
    try {

        const reqBody = req.body
        let existingUser = await getUser(reqBody.email, 'email');

        if (!existingUser) {
            return sendResponse(res, constants.WEB_STATUS_CODE.NOT_FOUND, constants.STATUS_CODE.NOT_FOUND, 'USER.email_not_found', {}, req.headers.lang);
        }

        if (existingUser && existingUser.verify_token == true) {
            return sendResponse(res, constants.WEB_STATUS_CODE.BAD_REQUEST, constants.STATUS_CODE.FAIL, 'USER.account_already_verify', {}, req.headers.lang);
        }

        let updated_at = await dateFormat.set_current_timestamp();

        tempTokens = await jwt.sign({
            data: reqBody.email
        }, JWT_SECRET, {
            expiresIn: constants.URL_EXPIRE_TIME
        })

        let updateData = {
            updated_at: updated_at,
            tempTokens: tempTokens
        }

        let conditionData = {
            email: reqBody.email
        }

        const user = await updateUser(conditionData, updateData);
        let verifyUrl = `${Keys.BASEURL}v1/users/account-verify?user_id=${existingUser._id}&emailVerificationToken=${tempTokens}`

        let sendMail = {
            'to': reqBody.email,
            'templateSlug': constants.EMAIL_TEMPLATE.RESEND_MAIL,
            'data': {
                // userName: reqBody.first_name,
                verifyUrl: verifyUrl
            }
        }


        let isSendEmail = await sendEmail(req, sendMail);
        if (isSendEmail) {
            console.log('email has been sent');
        } else {
            console.log('email has not been sent');
        }

        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.resend_email_success', user, req.headers.lang);

    } catch (err) {
        console.log(err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}

exports.createStudent = async (req, res, next) => {
    try {
        const reqBody = req.body
        reqBody.user_type = constants.USER_TYPE.STUDENT

        let existingUser = await getUser(reqBody.register_id, 'register_id');

        console.log("existingUser...", existingUser)

        if (existingUser) {
            return sendResponse(res, constants.WEB_STATUS_CODE.BAD_REQUEST, constants.STATUS_CODE.FAIL, 'USER.register_id_already_exist', {}, req.headers.lang);
        }

        reqBody.password = await bcrypt.hash(reqBody.password, 10);
        reqBody.created_at = await dateFormat.set_current_timestamp();
        reqBody.updated_at = await dateFormat.set_current_timestamp();

        const user = await Usersave(reqBody);
        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.create_student_success', user, req.headers.lang);

    } catch (err) {
        console.log("err........", err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}

exports.createFaculty = async (req, res, next) => {
    try {
        const reqBody = req.body
        reqBody.user_type = constants.USER_TYPE.FACULTY

        let existingUser = await getUser(reqBody.register_id, 'register_id');

        if (existingUser) {
            return sendResponse(res, constants.WEB_STATUS_CODE.BAD_REQUEST, constants.STATUS_CODE.FAIL, 'USER.register_id_already_exist', {}, req.headers.lang);
        }

        reqBody.password = await bcrypt.hash(reqBody.password, 10);
        reqBody.created_at = await dateFormat.set_current_timestamp();
        reqBody.updated_at = await dateFormat.set_current_timestamp();

        const user = await Usersave(reqBody);
        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.create_faculty_success', user, req.headers.lang);

    } catch (err) {
        console.log("err........", err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}

exports.getAllStudents = async (req, res) => {

    try {

        let {
            limit,
            page,
            sortBy,
            q
        } = req.query


        limit = +limit || constants.LIMIT;
        page = +page || constants.PAGE;

        const sort = {};
        const search = q ? q : ''; // for searching
        if (sortBy) {
            const parts = sortBy.split(':');
            field = parts[0];
            parts[1] === 'desc' ? value = -1 : value = 1;
        } else {
            field = "created_at",
                value = 1;
        }

        var query = {
            deleted_at: {
                $eq: null
            },
            user_type: constants.USER_TYPE.STUDENT,
        }
        if (search) {
            query.$or = [{
                    'first_name': new RegExp(search, 'i')
                },
                {
                    'last_name': new RegExp(search, 'i')
                },
                {
                    'email': new RegExp(search, 'i')
                },
            ]
        }
        let total = await User.countDocuments(query)

        let userData

        if (limit == -1) {
            userData = await User.find(query)
                .sort({
                    [field]: value
                })
                .lean();
        } else {

            userData = await User.find(query)
                .sort({
                    [field]: value
                })
                .skip((page - 1) * limit)
                .limit(limit)
                .lean();
        }

        let data = {
            rows: userData,
            page,
            limit,
            total
        }

        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.get_student_success', data, req.headers.lang);

    } catch (err) {
        console.log("err........", err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}


exports.getAllFaculties = async (req, res) => {

    try {


        let {
            limit,
            page,
            sortBy,
            q
        } = req.query


        limit = +limit || constants.LIMIT;
        page = +page || constants.PAGE;

        const sort = {};
        const search = q ? q : ''; // for searching
        if (sortBy) {
            const parts = sortBy.split(':');
            field = parts[0];
            parts[1] === 'desc' ? value = -1 : value = 1;
        } else {
            field = "created_at",
                value = 1;
        }

        let query = {
            deleted_at: {
                $eq: null
            },
            user_type: constants.USER_TYPE.FACULTY,
        }
        if (search) {
            query.$or = [{
                    'first_name': new RegExp(search, 'i')
                },
                {
                    'last_name': new RegExp(search, 'i')
                },
                {
                    'email': new RegExp(search, 'i')
                },
            ]
        }
        let total = await User.countDocuments(query)

        let userData

        if (limit == -1) {
            userData = await User.find(query)
                .sort({
                    [field]: value
                })
                .lean();
        } else {

            userData = await User.find(query)
                .sort({
                    [field]: value
                })
                .skip((page - 1) * limit)
                .limit(limit)
                .lean();
        }

        let data = {
            rows: userData,
            page,
            limit,
            total
        }

        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.get_faculty_success', data, req.headers.lang);

    } catch (err) {
        console.log("err........", err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}

exports.updateCourse = async (req, res, next) => {
    try {
        const reqBody = req.body
        reqBody.updated_at = await dateFormat.set_current_timestamp();

        const data = await Course.findByIdAndUpdate(reqBody._id, reqBody);

        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'COURSE.name_update_success', data, req.headers.lang);

    } catch (err) {
        console.log(err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}

exports.createCourse = async (req, res, next) => {
    try {
        const reqBody = req.body

        reqBody.created_at = await dateFormat.set_current_timestamp();
        reqBody.updated_at = await dateFormat.set_current_timestamp();

        let course = new Course(reqBody)
        let data = await course.save()

        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'COURSE.create_course_success', data, req.headers.lang);

    } catch (err) {
        console.log("err........", err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}


exports.courseList = async (req, res, next) => {
    try {

        let {
            limit,
            page,
            status,
            sortBy,
            q
        } = req.query


        limit = +limit || constants.LIMIT;
        page = +page || constants.PAGE;


        const sort = {};
        const time_stamp = req.query.last_sync_at || "0";
        var field = 'created_at',
            value = 1;
        const search = q ? q : ''; // for searching
        if (sortBy) {
            const parts = sortBy.split(':');
            field = parts[0];
            parts[1] === 'desc' ? value = -1 : value = 1;
        }

        let query = status ? {
            status: status
        } : {}


        if (search) {
            query.$or = [{
                'name': new RegExp(search, 'i')
            }]
        }

        query.$and = [{
            updated_at: {
                $gte: time_stamp
            }
        }];

        console.log("query.....", query)

        const tagCourses = await Course.countDocuments(query)

        let course

        if (limit == -1) {
            course = await Course.find(query).sort({
                [field]: value
            })
        } else {
            course = await Course.find(query).sort({
                [field]: value
            }).skip((page - 1) * limit).limit(limit)
        }

        let data = {}
        data.rows = course;
        data.total = tagCourses;
        data.limit = limit;
        data.page = page;

        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.create_subject_success', data, req.headers.lang);

    } catch (err) {
        console.log("err........", err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}



exports.assignCourseFaculty = async (req, res, next) => {
    try {
        const reqBody = req.body

        console.log("reqBody.user_id...", reqBody)

        const user = await User.findById(reqBody.user_id)
        const course = await Course.findById(reqBody.course_id)

        console.log("user...", user)
        console.log("course...", course)

        if (!user) return sendResponse(res, constants.WEB_STATUS_CODE.NOT_FOUND, constants.STATUS_CODE.NOT_FOUND, 'FACULTY.faculty_not_found', {}, req.headers.lang);
        if (!course) return sendResponse(res, constants.WEB_STATUS_CODE.NOT_FOUND, constants.STATUS_CODE.NOT_FOUND, 'COURSE.course_not_found', {}, req.headers.lang);

        reqBody.created_at = await dateFormat.set_current_timestamp();
        reqBody.updated_at = await dateFormat.set_current_timestamp();

        let courseFaculty = new CourseFaculty(reqBody)
        let data = await courseFaculty.save()

        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.create_subject_success', data, req.headers.lang);

    } catch (err) {
        console.log("err........", err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}

exports.selectCourse = async (req, res, next) => {
    try {
        let course_ids = req.body.course_ids

        // const course = await Course.findById(reqBody.course_id)
        // console.log("course...",course)

        // if (!course) return sendResponse(res, constants.WEB_STATUS_CODE.NOT_FOUND, constants.STATUS_CODE.NOT_FOUND, 'COURSE.course_not_found', {}, req.headers.lang);
        
        let current_time = await dateFormat.set_current_timestamp();

        console.log("course_ids...",course_ids)

        let bodyArr = []



        course_ids.map( e => {
            let obj = {}
            obj.user_id = req.user._id,
            obj.course_id = e,
            obj.created_at = current_time
            obj.updated_at = current_time

            bodyArr.push(obj)
            // return e
        })

        console.log("course_ids..2.",bodyArr)
        console.log("course_ids..3.",course_ids)

        let data = await CourseStudent.insertMany(bodyArr)
        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.select_subject_success', data, req.headers.lang);

    } catch (err) {
        console.log("err........", err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}



exports.studentCourseList = async (req, res, next) => {
    try {

        const data = await CourseStudent.aggregate([
            {
                $match: {
                    user_id: req.user._id
                }
            },
            {
                $lookup: {
                    from: "courses",
                    localField: "course_id",
                    foreignField: "_id",
                    as: "course_data"
                }
            },
            {
                $unwind: '$course_data',
            },
            // {
            //     $addfields: {
            //         "name": '$course_data.name'
            //     }
            // }

        ])


        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'COURSE.get_all_courese_assign', data, req.headers.lang);

    } catch (err) {
        console.log("err........", err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}

exports.facultyCourseList = async (req, res, next) => {
    try {

        const data = await CourseFaculty.aggregate([
            {
                $match: {
                    user_id: req.user._id
                }
            },
            {
                $lookup: {
                    from: "courses",
                    localField: "course_id",
                    foreignField: "_id",
                    as: "course_data"
                }
            },
            {
                $unwind: '$course_data',
            }
        ])


        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS,'COURSE.get_all_courese_assign', data, req.headers.lang);

    } catch (err) {
        console.log("err........", err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}

exports.addStudentAttendance = async (req, res, next) => {
    try {
        let course_id = req.body.course_id
        let student_ids = req.body.student_ids

        console.log("student_ids...",student_ids)
        
        let current_time = await dateFormat.set_current_timestamp();

        let bodyArr = []

        student_ids.map( e => {
            let obj = {}
            obj.faculty_id = req.user._id,
            obj.student_id = e.student_id,
            obj.is_present = e.is_present,
            obj.course_id = course_id
            obj.created_at = current_time
            obj.updated_at = current_time
            bodyArr.push(obj)
        })

        console.log("bodyArr...",bodyArr)

        let data = await AttendanceStudent.insertMany(bodyArr)
        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'ATTENDANCE.add_student_attendance', data, req.headers.lang);

    } catch (err) {
        console.log("err........", err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}

exports.getStudentAssignments = async (req, res, next) => {
    try {

        let queryObj = {
            user_id: req.user._id
        }

        let course_id = req.query.course_id
        if (course_id) {
            queryObj.course_id = course_id
        }

        let totalAssignment = await AssignmentStudent.find(queryObj)
        console.log("AssignmentStudent...",totalAssignment)

        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'ATTENDANCE.get_student_attendance', totalAssignment, req.headers.lang);

    } catch (err) {
        console.log(err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}
exports.getStudentAttendance = async (req, res, next) => {
    try {

        let queryObj = {
            student_id: req.user._id
        }

        let course_id = req.query.course_id
        if (course_id) {
            queryObj.course_id = course_id
        }
        let resultData = await AttendanceStudent.find(queryObj);
        let totalAttendance = await AttendanceStudent.countDocuments(queryObj)
        queryObj.is_present = true
        let presentAttendance = await AttendanceStudent.countDocuments(queryObj)

        let presentAttendancePercentage = ((presentAttendance/totalAttendance) * 100).toFixed(2)


        let resObj = {
            resultData,
            totalAttendance, 
            presentAttendance,
            presentAttendancePercentage
        }

        console.log("AttendanceStudent...",totalAttendance, presentAttendance)

        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'ATTENDANCE.get_student_attendance', resObj, req.headers.lang);

    } catch (err) {
        console.log(err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}

exports.addFacultyAttendance = async (req, res, next) => {
    try {

        let faculty_ids = req.body.faculty_ids

        console.log("faculty_ids...",faculty_ids)
        
        let current_time = await dateFormat.set_current_timestamp();

        let bodyArr = []

        faculty_ids.map( e => {
            let obj = {}
            obj.faculty_id = e.faculty_id,
            obj.is_present = e.is_present,
            obj.created_at = current_time
            obj.updated_at = current_time
            bodyArr.push(obj)
        })

        console.log("bodyArr...",bodyArr)

        let data = await AttendanceFaculty.insertMany(bodyArr)
        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'ATTENDANCE.add_faculty_attendance', data, req.headers.lang);

    } catch (err) {
        console.log("err........", err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}


exports.getFacultyAttendance = async (req, res, next) => {
    try {

        let queryObj = {
            faculty_id: req.user._id
        }

        console.log("queryObj...",queryObj)

        let totalAttendance = await AttendanceFaculty.countDocuments(queryObj)
        queryObj.is_present = true
        let presentAttendance = await AttendanceFaculty.countDocuments(queryObj)

        let presentAttendancePercentage = ((presentAttendance/totalAttendance) * 100).toFixed(2)

        let resObj = {
            totalAttendance, 
            presentAttendance,
            presentAttendancePercentage
        }

        console.log("AttendanceStudent...",totalAttendance, presentAttendance)

        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'ATTENDANCE.get_faculty_attendance', resObj, req.headers.lang);

    } catch (err) {
        console.log(err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}

exports.addAnnouncement = async (req, res, next) => {
    try {
        const reqBody = req.body

        reqBody.created_at = await dateFormat.set_current_timestamp();
        reqBody.updated_at = await dateFormat.set_current_timestamp();

        let announcement = new Announcement(reqBody)
        let data = await announcement.save()

        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.create_announcement', data, req.headers.lang);

    } catch (err) {
        console.log("err........", err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}


exports.getAllAnnouncement = async (req, res, next) => {
    try {

        let {
            limit,
            page,
            sortBy,
            q
        } = req.query


        limit = +limit || constants.LIMIT;
        page = +page || constants.PAGE;

        const sort = {};
        const search = q ? q : ''; // for searching
        if (sortBy) {
            const parts = sortBy.split(':');
            field = parts[0];
            parts[1] === 'desc' ? value = -1 : value = 1;
        } else {
            field = "created_at",
            value = -1;
        }

        var query = {
            deleted_at: {
                $eq: null
            },
        }
        if (search) {
            query.$or = [{
                    'title': new RegExp(search, 'i')
                },
                {
                    'category': new RegExp(search, 'i')
                },
                {
                    'description': new RegExp(search, 'i')
                },
            ]
        }
        let total = await Announcement.countDocuments(query)

        let announcementData

        if (limit == -1) {
            announcementData = await Announcement.find(query)
                .sort({
                    [field]: value
                })
                .lean();
        } else {

            announcementData = await Announcement.find(query)
                .sort({
                    [field]: value
                })
                .skip((page - 1) * limit)
                .limit(limit)
                .lean();
        }

        let data = {
            rows: announcementData,
            page,
            limit,
            total
        }

        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.get_student_success', data, req.headers.lang);

    } catch (err) {
        console.log("err........", err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}

exports.createProgram = async (req, res, next) => {
    try {
        const reqBody = req.body

        reqBody.created_at = await dateFormat.set_current_timestamp();
        reqBody.updated_at = await dateFormat.set_current_timestamp();

        let programs = new Programs(reqBody)
        let data = await programs.save()

        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'PROGRAM.create_program_success', data, req.headers.lang);

    } catch (err) {
        console.log("err........", err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}

exports.updateProgram = async (req, res, next) => {
    try {
        const reqBody = req.body
        reqBody.updated_at = await dateFormat.set_current_timestamp();

        const data = await Programs.findByIdAndUpdate(reqBody._id, reqBody);

        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'PROGRAM.name_update_success', data, req.headers.lang);

    } catch (err) {
        console.log(err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'PROGRAM.general_error_content', err.message, req.headers.lang)
    }
}

exports.programList = async (req, res, next) => {
    try {

        let {
            limit,
            page,
            status,
            sortBy,
            q
        } = req.query


        limit = +limit || constants.LIMIT;
        page = +page || constants.PAGE;


        const sort = {};
        const time_stamp = req.query.last_sync_at || "0";
        var field = 'created_at',
            value = 1;
        const search = q ? q : ''; // for searching
        if (sortBy) {
            const parts = sortBy.split(':');
            field = parts[0];
            parts[1] === 'desc' ? value = -1 : value = 1;
        }

        let query = status ? {
            status: status
        } : {}


        if (search) {
            query.$or = [{
                'name': new RegExp(search, 'i')
            }]
        }

        query.$and = [{
            updated_at: {
                $gte: time_stamp
            }
        }];

        console.log("query.....", query)

        const totalPrograms = await Programs.countDocuments(query)

        let programs

        if (limit == -1) {
            programs = await Programs.find(query).sort({
                [field]: value
            })
        } else {
            programs = await Programs.find(query).sort({
                [field]: value
            }).skip((page - 1) * limit).limit(limit)
        }

        let data = {}
        data.rows = programs;
        data.total = totalPrograms;
        data.limit = limit;
        data.page = page;

        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'PROGRAM.get_program_list', data, req.headers.lang);

    } catch (err) {
        console.log("err........", err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}

exports.programDetails = async (req, res, next) => {
    try {
    console.log("11111")
        let programId = req.params.program_id
        let userDetails = await Programs.findById(programId).lean()

        delete userDetails.password;
        delete userDetails.tokens;

        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.get_user_profile', userDetails, req.headers.lang);

    } catch (err) {
        console.log(err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}

exports.uploadExamTimeTable = async (req, res, next) => {
    try {
    console.log("11111", req.files)

    if (req.files) {
        console.log("reqfile yes", req.files.file[0].path)
        // reqBody.logo = req.files.logo[0].location
    }

    let adminData = await Admin.findOne({ item: "exam-time-table" })

    let data

    if (adminData){
        console.log("111")
        adminData.path = req.files.file[0].path
        console.log("adminData....",adminData)
        data = await adminData.save()
    } else {
        console.log("222")
        let announcement = new Admin({ item: "exam-time-table", path :req.files.file[0].path })
        data = await announcement.save()
    }

        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.upload_time_table', {}, req.headers.lang);

    } catch (err) {
        console.log(err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}

exports.uploadProfilePic = async (req, res, next) => {
    try {
    console.log("11111", req.body.user_id)
    console.log("11111", req.files.user_id)

    if (req.files) {
        console.log("reqfile yes", req.files.profile_pic[0].path)

        let userDetails = await User.findById(req.body.user_id)
        userDetails.profile_pic = req.files.profile_pic[0].path

        let data = await userDetails.save()

        console.log("data...",data);

        return sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.upload_time_table', data, req.headers.lang);

    } else{
        return sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.upload_time_table', {}, req.headers.lang);
    }

    } catch (err) {
        console.log(err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}



exports.uploadAadhaarCard = async (req, res, next) => {
    try {
    console.log("11111", req.body.user_id)
    console.log("11111", req.body.user_id)

    if (req.files) {
        console.log("reqfile yes", req.files.aadhaar_card[0].path)

        let userDetails = await User.findById(req.body.user_id)
        userDetails.aadhaar_card = req.files.aadhaar_card[0].path

        let data = await userDetails.save()

        console.log("data...",data);

        return sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.upload_time_table', data, req.headers.lang);

    } else{
        return sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.upload_time_table', {}, req.headers.lang);
    }

    } catch (err) {
        console.log(err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}
exports.uploadAssignmentStudent = async (req, res, next) => {
    try {
    console.log("11111", req.body.course_id)
    console.log("11111", req.files)
    let reqBody = req.body
    if (req.files) {
        console.log("reqfile yes", req.files.assignmentstudent[0].path)
        reqBody.created_at = await dateFormat.set_current_timestamp();
        reqBody.updated_at = await dateFormat.set_current_timestamp();
        reqBody.assignmentfile = req.files.assignmentstudent[0].path;
        let course = new AssignmentStudent(reqBody)
        let data = await course.save()

        console.log("data...",data);

        return sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.upload_student_assignment', data, req.headers.lang);

    } else{
        return sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.upload_time_table', {}, req.headers.lang);
    }

    } catch (err) {
        console.log(err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}
exports.uploadAssignment = async (req, res, next) => {
    try {
    console.log("11111", req.body.course_id)
    console.log("11111", req.files)

    if (req.files) {
        console.log("reqfile yes", req.files.assignment[0].path)

        let userDetails = await Assignment.findById(req.body.assignment_id)
        userDetails.assignment = req.files.assignment[0].path

        let data = await userDetails.save()

        console.log("data...",data);

        return sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.upload_time_table', data, req.headers.lang);

    } else{
        return sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.upload_time_table', {}, req.headers.lang);
    }

    } catch (err) {
        console.log(err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}

exports.uploadTimeTable = async (req, res, next) => {
    try {
    console.log("11111", req.files)

    if (req.files) {
        console.log("reqfile yes", req.files.timeTable[0].path)
    }

    let adminData = await Admin.findOne({ item: "time-table" })

    let data

    if (adminData){
        console.log("111")
        adminData.path = req.files.timeTable[0].path
        console.log("adminData....",adminData)
        data = await adminData.save()
    } else {
        console.log("222")
        let announcement = new Admin({ item: "time-table", path :req.files.file[0].path })
        data = await announcement.save()
    }

        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.upload_time_table', {}, req.headers.lang);

    } catch (err) {
        console.log(err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}

exports.getTimeTable = async (req, res, next) => {
    try {

        let adminData = await Admin.findOne({ item: "time-table" }).lean()

        var path = adminData.path.replace('public/','');


        adminData.path = "safe-atoll-64757.herokuapp.com/"+path


        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.logout_success', adminData, req.headers.lang);

    } catch (err) {
        console.log(err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}

exports.getExamTimeTable = async (req, res, next) => {
    try {

        let adminData = await Admin.findOne({ item: "exam-time-table" }).lean()

        var path = adminData.path.replace('public/','').replace(/\\/g, "/");
        adminData.path = "safe-atoll-64757.herokuapp.com/"+path
        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.logout_success', adminData, req.headers.lang);

    } catch (err) {
        console.log(err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}
exports.getAssignmentFile = async (req, res, next) => {
    try {
        let adminData = await Assignment.findById(req.params.assignment_id)
console.log(adminData);
        var path = adminData.assignment.replace('public/','').replace(/\\/g, "/");
        adminData.path = "safe-atoll-64757.herokuapp.com/"+path
        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.get_file', adminData, req.headers.lang);

    } catch (err) {
        console.log(err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}
exports.getStudentAssignmentFile = async (req, res, next) => {
    try {
        let adminData = await AssignmentStudent.findById(req.params.assignment_id)
console.log(adminData);
        var path = adminData.assignmentfile.replace('public/','').replace(/\\/g, "/");
        adminData.path = "safe-atoll-64757.herokuapp.com/"+path
        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.get_file', adminData, req.headers.lang);

    } catch (err) {
        console.log(err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}
exports.deleteUser = async (req, res, next) => {
    try {
        let userId = req.params.user_id
        let userDetails = await User.findById(userId).lean()

        console.log("userDetails",userDetails)

        if (userDetails) {

        let message = userDetails.type == 2 ? 'USER.delete_faculty' : 'USER.delete_student'

        await User.findByIdAndDelete(userId)
        return sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, message, {}, req.headers.lang);
        } else {
            return sendResponse(res, constants.WEB_STATUS_CODE.BAD_REQUEST, constants.STATUS_CODE.FAIL, 'USER.user_not_found', {}, req.headers.lang);
        }

    } catch (err) {
        console.log(err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}

exports.deleteProgram = async (req, res, next) => {
    try {
        let userId = req.params.program_id
        let userDetails = await Programs.findById(userId).lean()

        console.log("userDetails",userDetails)
        if (userDetails) {
        await Programs.findByIdAndDelete(userId)
        return sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.delete_program', {}, req.headers.lang);
        } else {
            return sendResponse(res, constants.WEB_STATUS_CODE.BAD_REQUEST, constants.STATUS_CODE.FAIL, 'USER.program_not_found', {}, req.headers.lang);
        }

    } catch (err) {
        console.log(err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}

exports.deleteCourse = async (req, res, next) => {
    try {
        let userId = req.params.course_id
        let userDetails = await Course.findById(userId).lean()

        console.log("userDetails",userDetails)

        if (userDetails) {
        await Course.findByIdAndDelete(userId)
        return sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.delete_course', {}, req.headers.lang);
        } else {
            return sendResponse(res, constants.WEB_STATUS_CODE.BAD_REQUEST, constants.STATUS_CODE.FAIL, 'USER.course_not_found', {}, req.headers.lang);
        }

    } catch (err) {
        console.log(err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}

exports.deleteAnnouncement = async (req, res, next) => {
    try {
        let userId = req.params.announcement_id
        let userDetails = await Announcement.findById(userId).lean()

        console.log("userDetails",userDetails)

        if (userDetails) {
        await Announcement.findByIdAndDelete(userId)
        return sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, "USER.delete_announcement", {}, req.headers.lang);
        } else {
            return sendResponse(res, constants.WEB_STATUS_CODE.BAD_REQUEST, constants.STATUS_CODE.FAIL, 'USER.announcement_not_found', {}, req.headers.lang);
        }

    } catch (err) {
        console.log(err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}

exports.getAnnouncement = async (req, res, next) => {
    try {

        let programId = req.params._id
        let announcementDetails = await Announcement.findById(programId).lean()

        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.get_announcement_details', announcementDetails, req.headers.lang);

    } catch (err) {
        console.log(err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}

exports.editAnnouncement = async (req, res, next) => {
    try {
        const reqBody = req.body
        reqBody.updated_at = await dateFormat.set_current_timestamp();

        const updateAnnouncement = await Announcement.findByIdAndUpdate(reqBody._id, reqBody)

        const data = await Announcement.findById(reqBody._id)

        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.announcemente_update_success', data, req.headers.lang);

    } catch (err) {
        console.log(err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}


exports.addExamSeating = async (req, res, next) => {
    try {
        const reqBody = req.body

        reqBody.created_at = await dateFormat.set_current_timestamp();
        reqBody.updated_at = await dateFormat.set_current_timestamp();

        let examSeating = new ExamSeating(reqBody)
        let data = await examSeating.save()

        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.create_announcement', data, req.headers.lang);

    } catch (err) {
        console.log("err........", err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}


exports.getAllExamSeating = async (req, res, next) => {
    try {

        let {
            limit,
            page,
            sortBy,
            q
        } = req.query


        limit = +limit || constants.LIMIT;
        page = +page || constants.PAGE;

        const sort = {};
        const search = q ? q : ''; // for searching
        if (sortBy) {
            const parts = sortBy.split(':');
            field = parts[0];
            parts[1] === 'desc' ? value = -1 : value = 1;
        } else {
            field = "created_at",
            value = -1;
        }

        var query = {
            deleted_at: {
                $eq: null
            },
        }
        if (search) {
            query.$or = [{
                    'title': new RegExp(search, 'i')
                },
                {
                    'category': new RegExp(search, 'i')
                },
                {
                    'description': new RegExp(search, 'i')
                },
            ]
        }
        let total = await ExamSeating.countDocuments(query)

        let examSeatingData

        if (limit == -1) {
            examSeatingData = await ExamSeating.find(query)
                .sort({
                    [field]: value
                })
                .lean();
        } else {

            examSeatingData = await ExamSeating.find(query)
                .sort({
                    [field]: value
                })
                .skip((page - 1) * limit)
                .limit(limit)
                .lean();
        }

        let data = {
            rows: examSeatingData,
            page,
            limit,
            total
        }

        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.get_student_success', data, req.headers.lang);

    } catch (err) {
        console.log("err........", err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}

exports.getExamSeating = async (req, res, next) => {
    try {

        let programId = req.params._id
        let announcementDetails = await ExamSeating.findById(programId).lean()

        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.get_announcement_details', announcementDetails, req.headers.lang);

    } catch (err) {
        console.log(err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}

exports.editExamSeating = async (req, res, next) => {
    try {
        const reqBody = req.body
        reqBody.updated_at = await dateFormat.set_current_timestamp();

        const updateAnnouncement = await ExamSeating.findByIdAndUpdate(reqBody._id, reqBody)

        const data = await ExamSeating.findById(reqBody._id)

        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.announcemente_update_success', data, req.headers.lang);

    } catch (err) {
        console.log(err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}



exports.deleteExamSeating = async (req, res, next) => {
    try {
        let userId = req.params._id
        let userDetails = await ExamSeating.findById(userId).lean()

        console.log("userDetails",userDetails)

        if (userDetails) {
        await ExamSeating.findByIdAndDelete(userId)
        return sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, "USER.delete_announcement", {}, req.headers.lang);
        } else {
            return sendResponse(res, constants.WEB_STATUS_CODE.BAD_REQUEST, constants.STATUS_CODE.FAIL, 'USER.announcement_not_found', {}, req.headers.lang);
        }

    } catch (err) {
        console.log(err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}
exports.addAssignment = async (req, res, next) => {
    try {
        const reqBody = req.body
        reqBody.assignment = null;
        reqBody.created_at = await dateFormat.set_current_timestamp();
        reqBody.updated_at = await dateFormat.set_current_timestamp();

        let assignment = new Assignment(reqBody)
        let data = await assignment.save()

        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.create_announcement', data, req.headers.lang);

    } catch (err) {
        console.log("err........", err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}


exports.getAllAssignment = async (req, res, next) => {
    try {

        let {
            limit,
            page,
            sortBy,
            q
        } = req.query


        limit = +limit || constants.LIMIT;
        page = +page || constants.PAGE;

        const sort = {};
        const search = q ? q : ''; // for searching
        if (sortBy) {
            const parts = sortBy.split(':');
            field = parts[0];
            parts[1] === 'desc' ? value = -1 : value = 1;
        } else {
            field = "created_at",
            value = -1;
        }

        var query = {
            deleted_at: {
                $eq: null
            },
        }
        if (search) {
            query.$or = [{
                    'title': new RegExp(search, 'i')
                },
                {
                    'category': new RegExp(search, 'i')
                },
                {
                    'description': new RegExp(search, 'i')
                },
            ]
        }
        let total = await Assignment.countDocuments(query)

        let assignmentData

        if (limit == -1) {
            assignmentData = await Assignment.find(query)
                .sort({
                    [field]: value
                })
                .lean();
        } else {

            assignmentData = await Assignment.find(query)
                .sort({
                    [field]: value
                })
                .skip((page - 1) * limit)
                .limit(limit)
                .lean();
        }

        let data = {
            rows: assignmentData,
            page,
            limit,
            total
        }

        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.get_student_success', data, req.headers.lang);

    } catch (err) {
        console.log("err........", err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}

exports.getAllAssignmentStudent = async (req, res, next) => {
    try {

        let {
            limit,
            page,
            sortBy,
            q
        } = req.query


        limit = +limit || constants.LIMIT;
        page = +page || constants.PAGE;

        const sort = {};
        const search = q ? q : ''; // for searching
        if (sortBy) {
            const parts = sortBy.split(':');
            field = parts[0];
            parts[1] === 'desc' ? value = -1 : value = 1;
        } else {
            field = "created_at",
            value = -1;
        }

        var query = {
            deleted_at: {
                $eq: null
            },
        }
        if (search) {
            query.$or = [{
                    'title': new RegExp(search, 'i')
                },
                {
                    'category': new RegExp(search, 'i')
                },
                {
                    'description': new RegExp(search, 'i')
                },
            ]
        }
        let total = await AssignmentStudent.countDocuments(query)

        let assignmentData

        if (limit == -1) {
            assignmentData = await AssignmentStudent.find(query)
                .sort({
                    [field]: value
                })
                .lean();
        } else {

            assignmentData = await AssignmentStudent.find(query)
                .sort({
                    [field]: value
                })
                .skip((page - 1) * limit)
                .limit(limit)
                .lean();
        }

        let data = {
            rows: assignmentData,
            page,
            limit,
            total
        }

        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.get_student_success', data, req.headers.lang);

    } catch (err) {
        console.log("err........", err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}

exports.getAssignment = async (req, res, next) => {
    try {

        let programId = req.params._id
        let announcementDetails = await Assignment.findById(programId).lean()

        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.get_announcement_details', announcementDetails, req.headers.lang);

    } catch (err) {
        console.log(err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}

exports.getAssignmentStudent = async (req, res, next) => {
    try {

        let programId = { user_id: req.params.student_id }
        let announcementDetails = await AssignmentStudent.find(programId)

        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.get_assignment_details', announcementDetails, req.headers.lang);

    } catch (err) {
        console.log(err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}

exports.editAssignment = async (req, res, next) => {
    try {
        const reqBody = req.body
        reqBody.updated_at = await dateFormat.set_current_timestamp();

        let announcementDetails = await Assignment.findByIdAndUpdate(reqBody._id, reqBody)

        const data = await Assignment.findById(reqBody.id)
console.log("edit ass", req.body,reqBody, data);
        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.announcemente_update_success', announcementDetails, req.headers.lang);

    } catch (err) {
        console.log(err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}



exports.deleteAssignment = async (req, res, next) => {
    try {

        console.log("******");


        let userId = req.params._id
        let userDetails = await Assignment.findById(userId).lean()

        console.log("userDetails",userDetails)

        if (userDetails) {
        await Assignment.findByIdAndDelete(userId)
        return sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, "USER.delete_announcement", {}, req.headers.lang);
        } else {
            return sendResponse(res, constants.WEB_STATUS_CODE.BAD_REQUEST, constants.STATUS_CODE.FAIL, 'USER.announcement_not_found', {}, req.headers.lang);
        }

    } catch (err) {
        console.log(err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const moment = require('moment');
const fs = require('fs');
const Keys = require('../../keys/keys')


const { sendResponse } = require('../../services/common.service')
const dateFormat = require('../../helper/dateformat.helper');

const { getUser, save } = require('../services/admin.service');
const constants = require('../../config/constants');

const User = require('../../models/user.model');
// const auth = require('../../middleware/auth.middleware')

const sendEmail = require('../../services/email.service');
const forgotPasswordTemplate = require('../services/emailTemplate/forgotPasswordTemplate');
const excel = require('node-excel-export');

exports.login = async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email: email, deleted_at: null });

        if (!user) {
            return sendResponse(res, constants.WEB_STATUS_CODE.BAD_REQUEST, constants.STATUS_CODE.FAIL, 'USER.invalid_username_password', {}, req.headers.lang);
        }
        if (!user.validPassword(password)) {
            return sendResponse(res, constants.WEB_STATUS_CODE.BAD_REQUEST, constants.STATUS_CODE.FAIL, 'USER.invalid_username_password', {}, req.headers.lang);
        }
        if (user.user_type !== constants.USER_TYPE.ADMIN) {
            return sendResponse(res, constants.WEB_STATUS_CODE.BAD_REQUEST, constants.STATUS_CODE.FAIL, 'GENERAL.unauthorized_user', {}, req.headers.lang);
        }

        const token = await user.generateAuthToken();
        user.tokens.token = token;
        await user.save();

        sendResponse(res, constants.WEB_STATUS_CODE.SUCCESS, constants.STATUS_CODE.SUCCESS, 'USER.login_success', user, req.headers.lang);
    } catch (err) {
        console.log("err........", err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}

exports.logout = async (req, res) => {
    try {
        req.user.tokens = []
        await req.user.save()

        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.logout_success', {}, req.headers.lang);
    } catch (err) {
        console.log("err........", err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}

exports.changePassword = async (req, res) => {
    try {
        let reqdata = req.body;

        let user = await User.findOne({ _id: req.user._id, deleted_at: null });

        if (!user) {
            return sendResponse(res, constants.WEB_STATUS_CODE.NOT_FOUND, constants.STATUS_CODE.NOT_FOUND, 'USER.userDetail_not_available', {}, req.headers.lang);
        }

        //checking for valid password
        if (!user.validPassword(reqdata.old_password)) {
            return sendResponse(res, constants.WEB_STATUS_CODE.NOT_FOUND, constants.STATUS_CODE.NOT_FOUND, 'USER.invalidOldPassword', {}, req.headers.lang);
        }

        user.password = await bcrypt.hash(reqdata.new_password, 10);
        user.updated_at = await dateFormat.set_current_timestamp();
        user.actual_updated_at = await dateFormat.set_current_timestamp();
        await user.save();

        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.resetPassword_success', {}, req.headers.lang);

    } catch (err) {
        console.log("err........", err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}

exports.forgotPassword = async (req, res) => {
    try {
        let email = req.body.email;
        var user = await User.findOne({ email, deleted_at: null });

        if (!user) {
            return sendResponse(res, constants.WEB_STATUS_CODE.NOT_FOUND, constants.STATUS_CODE.NOT_FOUND, 'USER.userDetail_not_available', {}, req.headers.lang);
        }

        var token = jwt.sign({ email }, constants.JWT_SECRET).toString();
        user.reset_password_token = token;
        //add hours to check expire time
        user.reset_password_expires = dateFormat.add_time_to_current_timestamp(1, 'hours');
        await user.save();

        const mailUrl = req.app.locals.base_url + '/api/v1/users/reset-password/';
        var logoURL = req.app.locals.base_url + '/' + constants.COMMONAPP_LOGO + '/' + constants.COMMONAPP_LOGO_IMAGE;

        await sendEmail(email, 'Password Reset', forgotPasswordTemplate({ url: mailUrl + token, logoURL: logoURL }));

        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.forgotPassword_email_success', {}, req.headers.lang);
    } catch (err) {
        console.log("err........", err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}


exports.getAllUsersProfile = async (req, res) => {

    try {

        const data = [];
        const sort = {};
        const search = req.query.q ? req.query.q : ''; // for searching
        if (req.query.sortBy) {
            const parts = req.query.sortBy.split(':');
            field = parts[0];
            parts[1] === 'desc' ? value = -1 : value = 1;
        } else {
            field = "created_at",
                value = 1;
        }
        const pageOptions = {
            page: parseInt(req.query.page) || constants.PAGE,
            limit: parseInt(req.query.limit) || constants.LIMIT
        }

        var query = {
            deleted_at: { $eq: null },
            user_type: constants.USER_TYPE.USER,
            verify_token: true
        }
        if (search) {
            query.$or = [
                { 'userName': new RegExp(search, 'i') },
                { 'email': new RegExp(search, 'i') },
            ]
        }
        var total = await User.countDocuments(query)
        var userData = await User.find(query)
            .sort({ [field]: value })
            .skip((pageOptions.page - 1) * pageOptions.limit)
            .limit(pageOptions.limit)
            .collation({ locale: "en" });

        let page = pageOptions.page;
        let limit = pageOptions.limit;

        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.user_data_retrieved_success', {userData, page, limit, total}, req.headers.lang);

    } catch (err) {
        console.log("err........", err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}


exports.activateDeactivateUser = async (req, res) => {
    try {
        const { status } = req.body;
        var user_type = constants.USER_TYPE.USER
        var id = req.params.id
        const userData = await User.findOne({ user_type: user_type, _id: id })

        if (!userData) return sendResponse(res, constants.WEB_STATUS_CODE.BAD_REQUEST, constants.STATUS_CODE.FAIL, 'USER.user_details_not_available', {}, req.headers.lang);

        var activate = constants.STATUS.ACTIVE;
        var intivate = constants.STATUS.INACTIVE
        var deActivate = constants.STATUS.DE_ACTIVE
        var message = '';
        userData.status = status;
        // userData._actionBy = req.user._id;
        userData.updated_at = dateFormat.set_current_timestamp();
        var data = await userData.save();
        if (status == activate) {
            message = 'USER.user_activation'
        } else if (status == deActivate) {
            message =  'USER.user_deactivate'
        } else {
            message =  'USER.user_inactivation'
        }
        // await commonFunction.getAWSImageUrl(data);
        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, message, data, req.headers.lang);

    } catch (err) {
        console.log("err........", err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}


exports.deleteUser = async (req, res) => {
    try {
        // const { status } = req.body;
        var user_type = constants.USER_TYPE.USER
        var id = req.params.id
        const userData = await User.findOne({ user_type: user_type, _id: id })

        if (!userData) return sendResponse(res, constants.WEB_STATUS_CODE.BAD_REQUEST, constants.STATUS_CODE.FAIL, 'USER.user_details_not_available', {}, req.headers.lang);


        userData.updated_at = dateFormat.set_current_timestamp();
        userData.deleted_at = dateFormat.set_current_timestamp();
        let data = await userData.save();
 
        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'USER.user_deleted', data, req.headers.lang);

    } catch (err) {
        console.log("err........", err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}

exports.getAllUsersExcel = async (req, res) => {
    try {

        if (req.query.sortBy) {
            const parts = req.query.sortBy.split(':');
            field = parts[0];
            parts[1] === 'desc' ? value = -1 : value = 1;
        } else {
            console.log(">>>>")
            field = "created_at",
                value = -1;
        }

          const userData = await User.find({user_type: 2, verify_token: true}).select('full_name email status created_at').sort({ [field]: value }).lean()

          console.log('userData.length....',userData)

          const styles = {
            headerDark: {
              font: {
                sz: 12,
                bold: true,
                // underline: true,
                align: 'center'
              }
            },
          };
        
          //Array of objects representing heading rows (very top)
          const heading = [
            [{value: 'a1', style: styles.headerDark}, {value: 'b1', style: styles.headerDark}, {value: 'c1', style: styles.headerDark}],
            ['All users details'] // <-- It can be only values
          ];
        
          //Here you specify the export structure
          const specification = {
            full_name: { // <- the key should match the actual data key
              displayName: 'Name', // <- Here you specify the column header
              headerStyle: styles.headerDark, // <- Header style
              cellFormat: function (value, row) { // <- Renderer function, you can access also any row.property
                return (value == null) ? '-' : value;
            },
              width: 120 // <- width in pixels
            },
            email: { // <- the key should match the actual data key
              displayName: 'Email', // <- Here you specify the column header
              headerStyle: styles.headerDark, // <- Header style
              cellFormat: function (value, row) { // <- Renderer function, you can access also any row.property
                return (value == null) ? '-' : value;
            },
              width: 250 // <- width in pixels
            },
            created_at: {
              displayName: 'Created At',
              headerStyle: styles.headerDark,
              cellFormat: function (value, row) { // <- Renderer function, you can access also any row.property
                let cdate = value * 1000
                return moment(cdate).format('YYYY-MM-DD')
              },
              width: 120 // <- width in chars (when the number is passed as string)
            },
            status: {
                displayName: 'Status',
                headerStyle: styles.headerDark,
                cellFormat: function (value, row) { // <- Renderer function, you can access also any row.property
                    return (value == 1) ? 'Active' : 'Inactive';
                },
                width: 120 // <- width in chars (when the number is passed as string)
              }
          }
        
          const merges = [
            { start: { row: 1, column: 1 }, end: { row: 2, column: 3 } }
          ]
        
          const report = excel.buildExport(
            [ // <- Notice that this is an array. Pass multiple sheets to create multi sheet report
              {
                name: 'Report', // <- Specify sheet name (optional)
                // heading: heading, // <- Raw heading array (optional)
                // merges: merges, // <- Merge cell ranges
                specification: specification, // <- Report specification
                data: userData // <-- Report data
              }
            ]
          );
        
          // You can then return this straight
        //   res.attachment('all_users_details.xlsx'); // This is sails.js specific (in general you need to set headers)

          current_time = await dateFormat.set_current_timestamp()

          let documentName = "public/documents/userDetails/all_users_details_"+current_time+".xlsx"
          let documentDir = "documents/userDetails/all_users_details_"+current_time+".xlsx"


          console.log("res....",report)

         await fs.writeFileSync(documentName, report);



        //   fs.writeFile(documentName, report, function(err) {
        //     if(err) {
        //         return console.log(err);
        //     }
        //     console.log("The file was saved!");
        //     let data = Keys.BASEURL+documentName
        //     console.log("data.....",data)
        //     sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'ADMIN.user_excel_file', data, req.headers.lang);
    
        // }); 

        let data = Keys.BASEURL+documentDir
        console.log("data.....",data)
        return sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'ADMIN.user_excel_file', data, req.headers.lang);

        //   return res.send(report);
    } catch (err) {
        console.log("err........", err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}
const dateFormat = require('../helper/dateformat.helper');
const constants = require('../config/constants');


module.exports = {

    'LOCATION': [
        {
            "title": "Welcome Mail",
            "keys": "email, userName",
            "subject": "HoopDNA - Welcome Mail",
            "body": "<p>Hello ,</p>\n\n<p>Welcome to Hoop DNA.</p>\n\n<p>Please verify your email:</p>\n\n<table border=\"0\" cellpadding=\"0\" cellspacing=\"0\" style=\"width:100%\">\n\t<tbody>\n\t\t<tr>\n\t\t\t<td>\n\t\t\t<table border=\"0\" cellpadding=\"0\" cellspacing=\"0\">\n\t\t\t\t<tbody>\n\t\t\t\t\t<tr>\n\t\t\t\t\t\t<td><a href=\"{!!!{verifyUrl}!!!}\" style=\"display: inline-block; padding: 16px 36px; font-family: 'Source Sans Pro', Helvetica, Arial, sans-serif; font-size: 16px; color: #FFFFFF; text-decoration: none; border-radius: 6px;background: #1BB3F5;\" target=\"_blank\">Verify your email</a></td>\n\t\t\t\t\t</tr>\n\t\t\t\t</tbody>\n\t\t\t</table>\n\t\t\t</td>\n\t\t</tr>\n\t</tbody>\n</table>\n\n<p><strong></p>",
            "slug": "WELCOME_MAIL",
            "status": constants.STATUS.ACTIVE,
            "id": 1,
            "createdAt": dateFormat.set_current_date(),
            "updatedAt": dateFormat.set_current_date(),
        },
        {
            "title": "Resend Mail",
            "keys": "email, userName",
            "subject": "HoopDNA - Resend Mail",
            "body": "<p>Hello ,</p>\n\n<p>Welcome to Hoop DNA.</p>\n\n<p>Please verify your email:</p>\n\n<table border=\"0\" cellpadding=\"0\" cellspacing=\"0\" style=\"width:100%\">\n\t<tbody>\n\t\t<tr>\n\t\t\t<td>\n\t\t\t<table border=\"0\" cellpadding=\"0\" cellspacing=\"0\">\n\t\t\t\t<tbody>\n\t\t\t\t\t<tr>\n\t\t\t\t\t\t<td><a href=\"{!!!{verifyUrl}!!!}\" style=\"display: inline-block; padding: 16px 36px; font-family: 'Source Sans Pro', Helvetica, Arial, sans-serif; font-size: 16px; color: #FFFFFF; text-decoration: none; border-radius: 6px;background: #1BB3F5;\" target=\"_blank\">Verify your email</a></td>\n\t\t\t\t\t</tr>\n\t\t\t\t</tbody>\n\t\t\t</table>\n\t\t\t</td>\n\t\t</tr>\n\t</tbody>\n</table>\n\n<p><strong></p>",
            "slug": "RESEND_MAIL",
            "status": constants.STATUS.ACTIVE,
            "id": 1,
            "createdAt": dateFormat.set_current_date(),
            "updatedAt": dateFormat.set_current_date(),
        },
        {
            "title": "Confirm Mail",
            "keys": "email, userName",
            "subject": "HoopDNA - Confirm Mail",
            "body": "<p>Hello ,</p>\n\n<p>Please verify your email:</p>\n\n<table border=\"0\" cellpadding=\"0\" cellspacing=\"0\" style=\"width:100%\">\n\t<tbody>\n\t\t<tr>\n\t\t\t<td>\n\t\t\t<table border=\"0\" cellpadding=\"0\" cellspacing=\"0\">\n\t\t\t\t<tbody>\n\t\t\t\t\t<tr>\n\t\t\t\t\t\t<td><a href=\"{!!!{verifyUrl}!!!}\" style=\"display: inline-block; padding: 16px 36px; font-family: 'Source Sans Pro', Helvetica, Arial, sans-serif; font-size: 16px; color: #FFFFFF; text-decoration: none; border-radius: 6px;background: #1BB3F5;\" target=\"_blank\">Verify your email</a></td>\n\t\t\t\t\t</tr>\n\t\t\t\t</tbody>\n\t\t\t</table>\n\t\t\t</td>\n\t\t</tr>\n\t</tbody>\n</table>\n\n<p><strong></p>",
            // "body": "<p>Hello ,</p>\n\n<p>Please verify your email: {!!!{verifyUrl}!!!}</p>\n\n<p>&nbsp;</p>",
            "slug": "CONFIRM_MAIL",
            "status": constants.STATUS.ACTIVE,
            "id": 1,
            "createdAt": dateFormat.set_current_date(),
            "updatedAt": dateFormat.set_current_date(),
        },
        {
            "title": "Reset Password",
            "keys": "email, userName",
            "subject": "HoopDNA - Reset Password",
            "body": "<p>Hello ,</p>\n\n<p>Below is the link to reset your password please check the url:</p>\n\n<table border=\"0\" cellpadding=\"0\" cellspacing=\"0\" style=\"width:100%\">\n\t<tbody>\n\t\t<tr>\n\t\t\t<td>\n\t\t\t<table border=\"0\" cellpadding=\"0\" cellspacing=\"0\">\n\t\t\t\t<tbody>\n\t\t\t\t\t<tr>\n\t\t\t\t\t\t<td><a href=\"{!!!{url}!!!}\" style=\"display: inline-block; padding: 16px 36px; font-family: 'Source Sans Pro', Helvetica, Arial, sans-serif; font-size: 16px; color: #FFFFFF; text-decoration: none; border-radius: 6px;background: #1BB3F5;\" target=\"_blank\">Reset Password</a></td>\n\t\t\t\t\t</tr>\n\t\t\t\t</tbody>\n\t\t\t</table>\n\t\t\t</td>\n\t\t</tr>\n\t</tbody>\n</table>\n\n<p><strong></p>",
            // "body": "<p>Hello ,</p>\n\n<p>Below is the link to reset your password please check the url:</p>\n\n<table border=\"0\" cellpadding=\"0\" cellspacing=\"0\" style=\"width:100%\">\n\t<tbody>\n\t\t<tr>\n\t\t\t<td>\n\t\t\t<table border=\"0\" cellpadding=\"0\" cellspacing=\"0\">\n\t\t\t\t<tbody>\n\t\t\t\t\t<tr>\n\t\t\t\t\t\t<td><a href=\"{!!!{url}!!!}\" style=\"display: inline-block; padding: 16px 36px; font-family: 'Source Sans Pro', Helvetica, Arial, sans-serif; font-size: 16px; color: #FFFFFF; text-decoration: none; border-radius: 6px;background: #1BB3F5;\" target=\"_blank\">Reset Password</a></td>\n\t\t\t\t\t</tr>\n\t\t\t\t</tbody>\n\t\t\t</table>\n\t\t\t</td>\n\t\t</tr>\n\t</tbody>\n</table>\n\n<p><strong>If that doesn&#39;t work, copy and paste the following link in your browser:</strong></p>\n\n<p><a href=\"{!!!{url}!!!}\" style=\"word-break: break-all;\" target=\"_blank\">{!!!{url}!!!}</a></p>\n\n<p>&nbsp;</p>",
            "slug": "PASSWORD_RESET",
            "status": constants.STATUS.ACTIVE,
            "id": 2,
            "createdAt": dateFormat.set_current_date(),
            "updatedAt": dateFormat.set_current_date(),
        },
        {
            "title": "Resend OTP",
            "keys": "userName",
            "subject": "HoopDNA - Verify Account",
            "body": "<p>Hi ,</p>\n\n<p>Welcome to twelfthman.</p>\n\n<p>Here is your OTP: {!!!{otp}!!!}</p>\n\n<p>&nbsp;</p>",
            "slug": "RESEND_OTP",
            "status": constants.STATUS.ACTIVE,
            "id": 3,
            "createdAt": dateFormat.set_current_date(),
            "updatedAt": dateFormat.set_current_date(),
        }
    ]
}   
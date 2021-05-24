const {
  validationResult
} = require('express-validator');
const {
  sendResponseValidation,
  responseIn
} = require('../services/common.service')
const constants = require('../config/constants')
const Keys = require('../keys/keys')
const fs = require('fs');

// show validation error message
exports.validatorFunc = (req, res, next) => {
  let errArray = {};
  const errors = validationResult(req);
  console.log("errors.....",errors)
  if (!errors.isEmpty()) {
    return sendResponseValidation(res, constants.WEB_STATUS_CODE.BAD_REQUEST, constants.STATUS_CODE.VALIDATION, errors.array()[0].msg, {}, req.headers.lang);
  }
  next();
};


exports.validatorFuncRender = (req, res, next) => {
  let errArray = {};
  const errors = validationResult(req);
  if (!errors.isEmpty()) {

    errMessage = responseIn(errors.array()[0].msg, req.headers.lang);

    let message = req.flash(
      'error',
      errMessage
    );

    return res.redirect(
      Keys.BASEURL + 'v1/web/reset-password?token=' + req.body.reset_password_token
    );
  }
  next();
};


exports.getFilePathWithoutPublic = async(fileName) => {
  let result = fileName;
  if(fileName){
      result = fileName.replace("public/","");
  }
  return result;
}



/**
 * Remove an image from folder.
 * @function
 * @param {String} imagePath - Give folder path where your image is stored 
 */
exports.removeFile = function(delPath){
  if (fs.existsSync(delPath)) {
      fs.unlinkSync(delPath);
  }
}

exports.getFilePathWithoutBaseUrl = async(fileName) => {
  let result = fileName;
  if(fileName){
      result = fileName.replace(Keys.BASEURL,"");
      result = "public"+result;
  }
  return result;
}

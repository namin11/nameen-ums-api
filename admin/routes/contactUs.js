var express = require('express');
var router = express.Router();

const admin_auth = require('../../middleware/admin.middleware')
const {contactus_validator} = require('../../validation/contactUs.validator');
const {validatorFunc} = require('../../helper/commonFunction.helper'); 

const {
  contactUs,
  getContactUsReq,
  getRequestDetail,
  closeContactRequest,
} = require('../controllers/contactUs.controller')

router.post('/contactUs', contactus_validator, validatorFunc , contactUs)
router.get('/getContactUsList' , getContactUsReq)
router.get('/getcontactUsDetails/:contactUsId' , getRequestDetail)
router.put('/closeContactRequest/:contactUsId' , closeContactRequest)

module.exports = router;

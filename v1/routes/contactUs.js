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
  deleteContactUs
} = require('../controllers/contactUs.controller')

// router.post('/contactUs', contactus_validator, validatorFunc , contactUs)
router.get('/get-contactUs-list' ,admin_auth, getContactUsReq)
router.get('/get-contactUs-details/:contactUsId' ,admin_auth, getRequestDetail)
router.put('/close-contactUs-request/:contactUsId' ,admin_auth, closeContactRequest)
router.delete('/delete-contactUs-request/:contactUsId' ,admin_auth, deleteContactUs)

module.exports = router;

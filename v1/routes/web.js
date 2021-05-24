const express = require('express');
const router = express.Router();


const {
    resetPasswordLinkVerification
  } = require('../controllers/web.controller')

router.get('/reset-password', resetPasswordLinkVerification);

module.exports = router;


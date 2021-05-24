const { body } = require('express-validator');

//validate user form detail
exports.contactus_validator = [
  body('username')
    .not()
    .isEmpty()
    .withMessage('valid_username')
    .trim(),
  body('email')
    .not()
    .isEmpty()
    .withMessage('email_required')
    .isEmail()
    .withMessage('valid_email')
    .trim(),
  body('subject')
    .not()
    .isEmpty()
    .withMessage('subject_required')
    .trim(),
  body('query')
    .not()
    .isEmpty()
    .withMessage('query_required.')
    .trim(),
];


exports.add_contactus_validator = [
  body('username')
    .not()
    .isEmpty()
    .withMessage('CONTACTUS_VALIDATION.valid_username')
    .trim(),
  body('email')
    .not()
    .isEmpty()
    .withMessage('CONTACTUS_VALIDATION.email_required')
    .isEmail()
    .withMessage('CONTACTUS_VALIDATION.valid_email')
    .trim(),
  body('query')
    .not()
    .isEmpty()
    .withMessage('CONTACTUS_VALIDATION.query_required')
    .trim(),
];
const { body } = require('express-validator');

//validate user form detail
exports.emailTemplateValidator = [
  body('title')
    .not()
    .isEmpty()
    .withMessage('EMAIL_TEMPLATE_VALIDATION.email_title')
    .trim()
    .isLength({ min: 3 })
    .withMessage('EMAIL_TEMPLATE_VALIDATION.email_title_length'),  
  body('keys')
    .not()
    .isEmpty()
    .withMessage('EMAIL_TEMPLATE_VALIDATION.email_keys')
    .trim(),
  body('subject')
    .not()
    .isEmpty()
    .withMessage('EMAIL_TEMPLATE_VALIDATION.email_subject')
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('EMAIL_TEMPLATE_VALIDATION.email_subject_length'),
  body('body')
    .not()
    .isEmpty()
    .withMessage('EMAIL_TEMPLATE_VALIDATION.email_body')
    .trim()
    .isLength({ min: 10 })
    .withMessage('EMAIL_TEMPLATE_VALIDATION.email_body_value'),
  body('status')
    .not()
    .isEmpty()
    .withMessage('EMAIL_TEMPLATE_VALIDATION.email_status')
    .trim()
    .isNumeric()
    .withMessage('EMAIL_TEMPLATE_VALIDATION.email_status_numeric'),
  
];
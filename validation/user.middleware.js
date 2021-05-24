// comment by jamal
//const { sendResponse } = require('../v1/services/common.service')
//const { check, validationResult } = require('express-validator');

// module.exports.user_validator = [
// check('first_name', 'please enter first name').not().isEmpty(),
// check('first_name').isAlpha().withMessage('USER_VALIDATION.enter correct first name'),
// check('last_name', 'please enter last name').not().isEmpty(),
// check('last_name').isAlpha().withMessage('USER_VALIDATION.enter correct last name'),
// check('email', 'please enter correct email').not().isEmpty().isEmail(),
// // check('password', 'please enter password').not().isEmpty(),
// // check('password').isLength({min: 8}).withMessage('USER_VALIDATION.password should be more then 8 character'),
// check("password", 'Password should be combination of one uppercase , one lower case, one special char, one digit and min 8 , max 20 char long').matches(/^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$.!%*#?&])[A-Za-z\d@$.!%*#?&]{8,}$/),


//   (req, res, next) => {
//     const errors = validationResult(req);
//     if (!errors.isEmpty()) {
//       sendResponse(res, 400, 'error', 'Somthing is wrong in signUp', errors.array());
//     } else {
//       next();
//     }
//   }
// ];

const { body, validationResult } = require('express-validator');

//validate user form detail
exports.user_validator = [
    body('email')
      .not()
      .isEmpty()
      .withMessage('USER_VALIDATION.email_required')
      .isEmail().withMessage('USER_VALIDATION.valid_email'),
      // .trim(),
    body('password')
      .not()
      .isEmpty()
      .withMessage('USER_VALIDATION.password_required')
      // .trim()
      // .isLength({ min: 6 })
      .matches(/^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$.!%*#?&])[A-Za-z\d@$.!%*#?&]{8,}$/)
      .withMessage('USER_VALIDATION.password_validation'),
      
    // body('first_name')
    //   .not()
    //   .isEmpty()
    //   .withMessage('USER_VALIDATION.first_name_required')
    //   .trim()
    //   .isString()
    //   .withMessage('USER_VALIDATION.first_name_valid')
    //   .isLength({ min: 2, max: 16 })
    //   .withMessage('USER_VALIDATION.FIRST_NAME_SIZE'),
    // body('last_name')
    //   .not()
    //   .isEmpty()
    //   .withMessage('USER_VALIDATION.last_name_required')
    //   .trim()
    //   .isString()
    //   .withMessage('USER_VALIDATION.last_name_valid')
    //   .isLength({ min: 2, max: 16 })
    //   .withMessage('USER_VALIDATION.last_name_size'),
];

exports.login_validator = [
  body('register_id')
    .not()
    .isEmpty()
    .withMessage('USER_VALIDATION.register_id_requiredd')
    .trim()
    .isLength({ min: 8, max: 8 })
    .withMessage('USER_VALIDATION.register_id_length'),

  body('password')
    .not()
    .isEmpty()
    .withMessage('USER_VALIDATION.password_required')
    // .trim()
    .matches(/^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$.!%*#?&])[A-Za-z\d@$.!%*#?&]{8,}$/)
    .withMessage('USER_VALIDATION.password_validation'),
];

exports.changePassword_validator = [
  body('old_password')
    .not()
    .isEmpty()
    .withMessage('USER_VALIDATION.old_password_required')
    .trim()
    .matches(/^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$.!%*#?&])[A-Za-z\d@$.!%*#?&]{8,}$/)
    .withMessage('USER_VALIDATION.old_password_validation'),
    // .isLength({ min: 6 })
    // .withMessage('USER_VALIDATION.old_password_size'),
    body('new_password')
    .not()
    .isEmpty()
    .withMessage('USER_VALIDATION.new_password_required')
    .trim()
    .matches(/^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$.!%*#?&])[A-Za-z\d@$.!%*#?&]{8,}$/)
    .withMessage('USER_VALIDATION.new_password_validation'),
    // .isLength({ min: 6 })
    // .withMessage('USER_VALIDATION.new_password_size'),
    body('confirm_password')
    .not()
    .isEmpty()
    .withMessage('USER_VALIDATION.confirm_password_required')
    .trim()
    .matches(/^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$.!%*#?&])[A-Za-z\d@$.!%*#?&]{8,}$/)
    .withMessage('USER_VALIDATION.confirm_password_validation'),
    // .isLength({ min: 6 })
    // .withMessage('USER_VALIDATION.confirm_password_size'),
];

exports.restPassword_validator = [
    body('new_password')
    .not()
    .isEmpty()
    .withMessage('USER_VALIDATION.new_password_required')
    .trim()
    .matches(/^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$.!%*#?&])[A-Za-z\d@$.!%*#?&]{8,}$/)
    .withMessage('USER_VALIDATION.new_password_validation'),
    // .isLength({ min: 6 })
    // .withMessage('USER_VALIDATION.new_password_size'),
    body('confirm_password')
    .not()
    .isEmpty()
    .withMessage('USER_VALIDATION.confirm_password_required')
    .trim()
    .matches(/^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$.!%*#?&])[A-Za-z\d@$.!%*#?&]{8,}$/)
    .withMessage('USER_VALIDATION.confirm_password_validation'),
    // .isLength({ min: 6 })
    // .withMessage('USER_VALIDATION.confirm_password_size'),
];

exports.forgotPassword_validator = [
  body('email')
      .not()
      .isEmpty()
      .withMessage('USER_VALIDATION.email_required')
      .isEmail().withMessage('USER_VALIDATION.valid_email')
      .trim()
];

exports.notification_validator = [
  body('daily_practice_remender')
  .not()
  .isEmpty()
  .withMessage('USER_VALIDATION.daily_practice_remender_required')
  .trim(),
  body('new_program_added')
  .not()
  .isEmpty()
  .withMessage('USER_VALIDATION.new_program_added_required')
  .trim(),
  body('subscription_remainder')
  .not()
  .isEmpty()
  .withMessage('USER_VALIDATION.subscription_remainder_required')
  .trim()
];


exports.socialLogin_validator = [
  body('social_id')
  .not()
  .isEmpty()
  .withMessage('USER_VALIDATION.social_id_required')
  .trim(),
  body('social_type')
  .not()
  .isEmpty()
  .withMessage('USER_VALIDATION.social_type_required')
  .trim()
  .matches(/^[1-3]$/)
  .withMessage('USER_VALIDATION.social_type_value'),
];


exports.update_validator1 = [
  // body('social_id')
  // .not()
  // .isEmpty()
  // .withMessage('USER_VALIDATION.social_id_required')
  // .trim(),
  // body('social_type')
  // .not()
  // .isEmpty()
  // .withMessage('USER_VALIDATION.social_type_required')
  // .trim()
  // .matches(/^[1-3]$/)
  // .withMessage('USER_VALIDATION.social_type_value'),
];


exports.update_validator = async (req, res, next) => {

  let screen = req.body.screen
console.log("screen......",screen)


module.exports = [
    body('daily_practice_remender')
    .not()
    .isEmpty()
    .withMessage('USER_VALIDATION.daily_practice_remender_required')
    .trim(),
    body('new_program_added')
    .not()
    .isEmpty()
    .withMessage('USER_VALIDATION.new_program_added_required')
    .trim(),
    body('subscription_remainder')
    .not()
    .isEmpty()
    .withMessage('USER_VALIDATION.subscription_remainder_required')
    .trim()
  ];

  // console.log("bb..........", bb)

  // return bb

}

exports.verify_android_purchase_token_validator = [
  body('package_name')
  .not()
  .isEmpty()
  .withMessage('VERIFY_TOKEN_VALIDATION.package_name_required')
  .trim(),
  body('product_id')
  .not()
  .isEmpty()
  .withMessage('VERIFY_TOKEN_VALIDATION.product_id_required')
  .trim(),
  body('purchase_token')
  .not()
  .isEmpty()
  .withMessage('VERIFY_TOKEN_VALIDATION.purchase_token_required')
  .trim()
  ];

  exports.verify_ios_purchase_token_validator = [
    body('apple_receipt')
    .not()
    .isEmpty()
    .withMessage('VERIFY_TOKEN_VALIDATION.apple_receipt_required')
    .trim(),
    body('transaction_id')
    .not()
    .isEmpty()
    .withMessage('VERIFY_TOKEN_VALIDATION.transaction_id_required')
    .trim()
    ];






//   let screen = req.body.screen

// console.log("screen......",screen)
// let a
// if (screen == 'theme') {
//    console.log("yessss")
// return [
// body('social_id')
// .not()
// .isEmpty()
// .withMessage('USER_VALIDATION.social_id_required')
// .trim(),
// body('social_type')
// .not()
// .isEmpty()
// .withMessage('USER_VALIDATION.social_type_required')
// .trim()
// .matches(/^[1-3]$/)
// .withMessage('USER_VALIDATION.social_type_value'),
// ]
// }

// return a




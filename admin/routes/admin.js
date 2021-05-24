var express = require('express');
var router = express.Router();

const { login_validator,changePassword_validator } = require('../../validation/user.middleware')
const admin_auth = require('../../middleware/admin.middleware')
const {validatorFunc} = require('../../helper/commonFunction.helper'); 

const {
  login,
  logout,
  changePassword,
  forgotPassword,
  getAllUsersProfile,
  activateDeactivateUser,
  deleteUser,
  getAllUsersExcel
} = require('../controllers/admin.controller')

router.post('/login', login_validator,validatorFunc, login)
router.post('/logout', logout)
router.post('/changePassword', changePassword_validator, validatorFunc, changePassword)
router.post('/forgotPassword', validatorFunc,forgotPassword)
router.get('/get-all-users', getAllUsersProfile);
router.put('/active-deactive-user/:id', activateDeactivateUser);
router.delete('/delete-user/:id', deleteUser);
router.get('/get-all-users-excel', admin_auth, getAllUsersExcel);

module.exports = router;

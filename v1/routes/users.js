var express = require('express');
var router = express.Router();
const { body } = require('express-validator');
var multer = require('multer');


var storage = multer.diskStorage({
  destination: (req, files, cb) => {
    if (files.fieldname == `file`) { cb(null, 'public/exam-time-table/'); }
    if (files.fieldname == `timeTable`) { cb(null, 'public/time-table/'); }
    if (files.fieldname == `profile_pic`) { cb(null, 'public/time-table/'); }
    if (files.fieldname == `aadhaar_card`) { cb(null, 'public/aadhaar-card/'); }
    if (files.fieldname == `assignment`) { cb(null, 'public/assignment/'); }
    if (files.fieldname == `assignmentstudent`) { cb(null, 'public/assignmentstudent/'); }

  },
  filename: (req, file, cb) => {
    if (file.originalname.indexOf(' ')) {
      file.originalname = file.originalname.replace(/ /g, '_');
    }
    var ext = file.originalname.split('.');
    var today = new Date();
    var dd = today.getDate();
    var mm = today.getMonth() + 1; //January is 0!

    var yyyy = today.getFullYear();
    if (dd < 10) {
      dd = '0' + dd;
    }
    if (mm < 10) {
      mm = '0' + mm;
    }
    var today = dd + '-' + mm + '-' + yyyy;

    let time = Date.now()
    cb(null, file.fieldname + '-' + time + '.' + ext[1]);
  }
});
const fileFilter = (req, file, cb) => {

  if (
    file.mimetype === "image/png" ||
    file.mimetype === "image/jpg" ||
    file.mimetype === "image/jpeg" ||
    file.mimetype === "application/pdf"
  ) {

    cb(null, true);
  } else {

    req.errorMessage = "File format should be PNG,JPG,JPEG";
    cb(null, false);
    //cb(new Error("File format should be PNG,JPG,JPEG"), false); // if validation failed then generate error
  }
};


const {authenticate, adminAuthenticate, facultyAuthenticate} = require('../../middleware/authenticate');
const { user_validator,
  login_validator,
  changePassword_validator,
  forgotPassword_validator,
  socialLogin_validator,
  restPassword_validator,
  update_validator
 } = require('../../validation/user.middleware')

const { add_contactus_validator } = require('../../validation/contactUs.validator');

const {validatorFunc, validatorFuncRender} = require('../../helper/commonFunction.helper'); 

var upload = multer({ storage: storage, fileFilter: fileFilter });

const {
  signUp, 
  login,
  accountVerify,
  emailVerify,
  forgotPassword,
  changePassword,
  resetPassword,
  getProfile,
  editProfile,
  editUserProfile,
  contactUs,
  editContactUs,                                                                                                                                                                                                                                                          
  userSocialLogin,
  logout,
  resendMail,
  emailVerifyPage,
  createStudent,
  createFaculty,
  getAllStudents,
  getAllFaculties,
  viewDetails,
  createCourse,
  updateCourse,
  courseList,
  assignCourseFaculty,
  selectCourse,
  studentCourseList,
  facultyCourseList,
  addStudentAttendance,
  getStudentAttendance,
  getStudentAssignments,
  addFacultyAttendance,
  getFacultyAttendance,
  addAnnouncement,
  getAllAnnouncement,
  editAnnouncement,
  getAnnouncement,
  createProgram,
  updateProgram,
  programList,
  programDetails,
  uploadExamTimeTable,
  getTimeTable,
  getExamTimeTable,
  getAssignmentFile,
  getStudentAssignmentFile,
  getAssignmentStudent,
  uploadProfilePic,
  uploadAadhaarCard,
  uploadAssignment,
  uploadAssignmentStudent,
  deleteUser,
  deleteProgram,
  deleteCourse,
  deleteAnnouncement,
  uploadTimeTable,
  addExamSeating,
  getExamSeating,
  editExamSeating,
  getAllExamSeating,
  deleteExamSeating,
  addAssignment,
  getAssignment,
  editAssignment,
  getAllAssignment,
  getAllAssignmentStudent,
  deleteAssignment
} = require('../controllers/user.controller')


const {
  getAllStudentResults,
  getStudentResults,
  createStudentResult,
  editStudentResult,
  deleteStudentResult,
  getStudentResultBySem
} = require('../controllers/studentResult.controller')

//Common

router.post('/login',login_validator, validatorFunc, login)
router.get('/account-verify', accountVerify)
router.post('/forgot-password', forgotPassword_validator, validatorFunc, forgotPassword)
router.put('/change-password', changePassword_validator,validatorFunc, authenticate, changePassword)
router.post('/reset-password', restPassword_validator,validatorFuncRender, resetPassword)
router.get('/',authenticate, getProfile)
router.put('/',authenticate, editProfile)

router.post('/resend-mail', forgotPassword_validator, validatorFunc, resendMail)
router.get('/logout',authenticate, logout)

router.get('/get-all-announcement', authenticate, getAllAnnouncement)
router.get('/program-details/:program_id',authenticate, programDetails) 
router.get('/get-time-table',authenticate, getTimeTable)
router.get('/get-exam-time-table',authenticate, getExamTimeTable)

router.get('/get-student-assignment-file/:student_id',authenticate, getAssignmentStudent)
router.get('/get-assignment-file/:assignment_id',authenticate, getAssignmentFile)
router.get('/get-student-assignment-file/:assignment_id',authenticate, getStudentAssignmentFile)

router.put('/edit-user-details',authenticate, editUserProfile)

//Admin
router.post('/create-student',login_validator, validatorFunc,adminAuthenticate, createStudent)
router.post('/create-faculty',login_validator, validatorFunc, adminAuthenticate, createFaculty)
router.get('/get-all-students', authenticate, getAllStudents)
router.get('/get-all-faculties', adminAuthenticate, getAllFaculties)
router.get('/user-details/user_id',authenticate, viewDetails)
router.post('/create-course',adminAuthenticate, createCourse)
router.post('/update-course',adminAuthenticate, updateCourse)
router.get('/course-list',authenticate, courseList)
router.post('/assign-course-faculty',adminAuthenticate, assignCourseFaculty)
router.post('/add-faculty-attendance',adminAuthenticate, addFacultyAttendance)
router.post('/add-announcement',adminAuthenticate, addAnnouncement)
router.get('/get-announcement/:_id',authenticate, getAnnouncement)
router.put('/edit-announcement',authenticate, editAnnouncement)
router.post('/create-program',adminAuthenticate, createProgram)
router.post('/update-program',adminAuthenticate, updateProgram)
router.get('/program-list',authenticate, programList)
// router.post('/upload-exam-time-table',adminAuthenticate, createProgram)

router.delete('/delete-user/:user_id',adminAuthenticate, deleteUser)
router.delete('/delete-program/:program_id',adminAuthenticate, deleteProgram)
router.delete('/delete-course/:course_id',adminAuthenticate, deleteCourse)
router.delete('/delete-announcement/:announcement_id',adminAuthenticate, deleteAnnouncement)
router.post('/upload-exam-time-table', authenticate, function (req, res, next) {
  try {

    req.errorMessage = "";
    next();
  } catch (error) {
    console.log("error...............", err)
    res.status(422).send(error.message)
  }
}, upload.fields([
  { name: 'file', maxCount: 1 },
]), function (req, res, next) {
  if (req.errorMessage != "") {
    console.log("error...............")
    var response = req.response;
    response.setMessage = req.errorMessage
    response.setStatus = 422;
    response.setErrorStack = req.errorMessage
    res.status(422).send(response);
  } else { next(); }

}, uploadExamTimeTable);

router.post('/upload-time-table', authenticate, function (req, res, next) {
  try {

    req.errorMessage = "";
    next();
  } catch (error) {
    console.log("error...............", err)
    res.status(422).send(error.message)
  }
}, upload.fields([
  { name: 'timeTable', maxCount: 1 },
]), function (req, res, next) {
  if (req.errorMessage != "") {
    console.log("error...............")
    var response = req.response;
    response.setMessage = req.errorMessage
    response.setStatus = 422;
    response.setErrorStack = req.errorMessage
    res.status(422).send(response);
  } else { next(); }

}, uploadTimeTable);

router.post('/upload-profile-pic', authenticate, function (req, res, next) {
  try {

    req.errorMessage = "";
    next();
  } catch (error) {
    console.log("error...............", err)
    res.status(422).send(error.message)
  }
}, upload.fields([
  { name: 'profile_pic', maxCount: 1 },
]), function (req, res, next) {
  if (req.errorMessage != "") {
    console.log("error...............")
    var response = req.response;
    response.setMessage = req.errorMessage
    response.setStatus = 422;
    response.setErrorStack = req.errorMessage
    res.status(422).send(response);
  } else { next(); }

}, uploadProfilePic);

router.post('/upload-aadhaar-card', authenticate, function (req, res, next) {
  try {

    req.errorMessage = "";
    next();
  } catch (error) {
    console.log("error...............", err)
    res.status(422).send(error.message)
  }
}, upload.fields([
  { name: 'aadhaar_card', maxCount: 1 },
]), function (req, res, next) {
  if (req.errorMessage != "") {
    console.log("error...............")
    var response = req.response;
    response.setMessage = req.errorMessage
    response.setStatus = 422;
    response.setErrorStack = req.errorMessage
    res.status(422).send(response);
  } else { next(); }

}, uploadAadhaarCard);

router.post('/upload-assignment', authenticate, function (req, res, next) {
  try {

    req.errorMessage = "";
    next();
  } catch (error) {
    console.log("error...............", err)
    res.status(422).send(error.message)
  }
}, upload.fields([
  { name: 'assignment', maxCount: 1 },
]), function (req, res, next) {
  if (req.errorMessage != "") {
    console.log("error...............")
    var response = req.response;
    response.setMessage = req.errorMessage
    response.setStatus = 422;
    response.setErrorStack = req.errorMessage
    res.status(422).send(response);
  } else { next(); }

}, uploadAssignment);

router.post('/upload-assignment-student', authenticate, function (req, res, next) {
  try {

    req.errorMessage = "";
    next();
  } catch (error) {
    console.log("error...............", err)
    res.status(422).send(error.message)
  }
}, upload.fields([
  { name: 'assignmentstudent', maxCount: 1 },
]), function (req, res, next) {
  if (req.errorMessage != "") {
    console.log("error...............")
    var response = req.response;
    response.setMessage = req.errorMessage
    response.setStatus = 422;
    response.setErrorStack = req.errorMessage
    res.status(422).send(response);
  } else { next(); }

}, uploadAssignmentStudent);

router.post('/add-examSeating',adminAuthenticate, addExamSeating)
router.get('/get-examSeating/:_id',authenticate, getExamSeating)
router.put('/edit-examSeating',authenticate, editExamSeating)
router.get('/get-all-examSeating', authenticate, getAllExamSeating)
router.delete('/delete-examSeating/:_id',adminAuthenticate, deleteExamSeating)


//Faculty
router.get('/faculty-course-list',authenticate, facultyCourseList)
router.post('/add-student-attendance',facultyAuthenticate, addStudentAttendance)
router.get('/get-faculty-attendance',authenticate, getFacultyAttendance)


//Students
router.post('/select-course',authenticate, selectCourse)
router.get('/student-course-list',authenticate, studentCourseList)
router.post('/contact-us', add_contactus_validator,validatorFunc,authenticate,contactUs)
router.post('/edit-contact-us', authenticate,editContactUs)

router.get('/get-student-attendance',authenticate, getStudentAttendance)

//assignment
router.post('/add-assignment',authenticate, addAssignment)
router.get('/get-assignment/:_id',authenticate, getAssignment)
router.put('/edit-assignment',authenticate, editAssignment)
router.get('/get-all-assignment', authenticate, getAllAssignment)
router.get('/get-all-assignment-student', authenticate, getAllAssignmentStudent)
router.get('/get-student-assignment', authenticate, getStudentAssignments)
router.delete('/delete-assignment/:_id',adminAuthenticate, deleteAssignment)




router.get('/all-student-result-list',authenticate, getAllStudentResults)
router.get('/student-result/:student_id', authenticate, getStudentResults)
router.post('/create-student-result', authenticate, createStudentResult);
router.put('/edit-student-result',authenticate, editStudentResult)
router.delete('/delete-student-result/:_id',authenticate, deleteStudentResult)
router.get('/student-result-sem', authenticate, getStudentResultBySem)


router.post('/')

module.exports = router;


const StudentResult = require('../../models/studentResult.model')
const { ObjectId } = require('mongoose').Types;
const AttendanceStudent = require('../../models/attendanceStudent.model')
const User = require('../../models/user.model');

exports.getAllStudentResult = async () => {
  try {
    const data = await StudentResult.find();
    const results = []
    for(let result of studentResult){
      const getStudent = await User.findById(result.student_id)
      console.log(getStudent);
    }
    return data;
  } catch (error) {
    throw error;
  }
};

exports.getStudentResultBySem = async (data) => {
  try {

      let queryObj = {
          student_id: data.user._id
      }

      let type = data.query.type
      let student_id = data.query.student_id
      if (type) {
          queryObj.type = type
          queryObj.student_id = student_id
      }
      let results = []
      let studentResult = await StudentResult.find(queryObj)
      for(let result of studentResult){
        queryObj.course_id =  `${ObjectId(result.course_id)}`
        console.log("queryObj", queryObj)
        let totalAttendance = await AttendanceStudent.countDocuments({
          student_id: queryObj.student_id,
          course_id: queryObj.course_id,
        })
        queryObj.is_present = true
        let presentAttendance = await AttendanceStudent.countDocuments({
          student_id: queryObj.student_id,
          course_id: queryObj.course_id,
          is_present: queryObj.is_present
        })
        let presentAttendancePercentage = presentAttendance > 0 && totalAttendance > 0 ? ((presentAttendance/totalAttendance) * 100).toFixed(2):0
        results.push({
            ...result._doc,
            totalAttendance, 
            presentAttendance,
            presentAttendancePercentage
        })
      }
      return results;

  } catch (err) {
    throw err;
  }
}

exports.getStudentResultByStudent = async studentId => {
  try {
    const data = await StudentResult.find({student_id:studentId})
    let queryObj = {
      student_id: ObjectId(studentId)
    }
    let results = []
    for(let result of data){
      queryObj.course_id =  ObjectId(result.course_id)
      console.log("queryObj", queryObj)
      let totalAttendance = await AttendanceStudent.countDocuments(queryObj)
      queryObj.is_present = true
      let presentAttendance = await AttendanceStudent.countDocuments(queryObj)
      let presentAttendancePercentage = presentAttendance > 0 && totalAttendance > 0 ? ((presentAttendance/totalAttendance) * 100).toFixed(2):0
      results.push({
          ...result._doc,
          totalAttendance, 
          presentAttendance,
          presentAttendancePercentage
      })
    }
    return results;
  } catch (error) {
    throw error;
  }
};

const mongoose = require('mongoose');
var Schema = mongoose.Schema;

var attendance_studentSchema = new mongoose.Schema({
    student_id: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: 'users'
    },
    faculty_id: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: 'users'
    },
    is_present: {
        type: Boolean,
        default: false
    },
    course_id: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: 'courses'
    },
    created_at: {
        type: Number,
    },
    updated_at: {
        type: Number,
    },
    deleted_at: {
        type: Number,
        default: null,
    }
});

const attendance_student = mongoose.model('attendance_student', attendance_studentSchema);
module.exports = attendance_student;
const mongoose = require('mongoose');
var Schema = mongoose.Schema;

var assignment_student = new mongoose.Schema({
    user_id: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: 'users'
    },
    course_id: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: 'courses'
    },
    assignment_id: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: 'assignment'
    },
    assignmentfile: {
        type: String,
        default: null
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

const AssignmentStudent = mongoose.model('assignmentstudent', assignment_student);
module.exports = AssignmentStudent;
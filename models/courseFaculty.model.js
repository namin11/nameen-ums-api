const mongoose = require('mongoose');
var Schema = mongoose.Schema;

var course_facultySchema = new mongoose.Schema({
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

const course_faculty = mongoose.model('course_faculty', course_facultySchema);
module.exports = course_faculty;
const mongoose = require('mongoose');
var Schema = mongoose.Schema;

var attendance_facultySchema = new mongoose.Schema({
    faculty_id: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: 'users'
    },
    is_present: {
        type: Boolean,
        default: false
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

const attendance_faculty = mongoose.model('attendance_faculty', attendance_facultySchema);
module.exports = attendance_faculty;
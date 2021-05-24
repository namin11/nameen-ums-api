const mongoose = require('mongoose');
var Schema = mongoose.Schema;

var assignmentSchema = new mongoose.Schema({
    course_id: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: 'courses'
    },
    description: {
        type: String,
        default: null,
        required: true
    },
    submission_date: {
        type: Number,
    },
    created_at: {
        type: Number,
    },
    updated_at: {
        type: Number,
    },
    assignment: {
        type: String,
        default: null
    },
    deleted_at: {
        type: Number,
        default: null,
    }
});

const Assignment = mongoose.model('assignment', assignmentSchema);
module.exports = Assignment;
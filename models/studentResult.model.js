const mongoose = require('mongoose');
var Schema = mongoose.Schema;

var studentResultSchema = new mongoose.Schema({
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
    course_id: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: 'courses'
    },
    ete: {
        type: Number,
        default: null,
    },
    mte: {
        type: Number,
        default: null,
    },
    ca1: {
        type: Number,
        default: null,
    },
    ca2: {
        type: Number,
        default: null,
    },
    ca3: {
        type: Number,
        default: null,
    },
    type: {
        type: Number,
        default: 1,// sem -1,2,3,4,5,6,7,8        
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

const StudentResult = mongoose.model('student_result', studentResultSchema);
module.exports = StudentResult;
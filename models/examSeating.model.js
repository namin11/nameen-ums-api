const mongoose = require('mongoose');
var Schema = mongoose.Schema;

var examSeatingSchema = new mongoose.Schema({
    course: {
        type: String,
        default: null,
        trim: true,
        required: true
    },
    course_name: {
        type: String,
        default: null    
    },
    room_number: {
        type: String,
        default: null
    },
    reporting_time: {
        type: String,
        default: null
    },
    date: {
        type: String,
        default: null
    },
    time: {
        type: String,
        default: null
    },
    status: {
        type: Number,
        default: 1
    },
    updated_at: {
        type: Number,
    },
    deleted_at: {
        type: Number,
        default: null,
    }
});

const examSeating = mongoose.model('examSeating', examSeatingSchema);
module.exports = examSeating;
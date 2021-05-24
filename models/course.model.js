const mongoose = require('mongoose');
var Schema = mongoose.Schema;

var courseSchema = new mongoose.Schema({
    code: {
        type: String,
        default: null,
        trim: true,
        required: true
    },
    name: {
        type: String,
        default: null,
        required: true
    },
    status: {
        type: Number,
        default: 1
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

const course = mongoose.model('course', courseSchema);
module.exports = course;
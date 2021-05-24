const mongoose = require('mongoose');
var Schema = mongoose.Schema;

var contactUsSchema = new mongoose.Schema({
    user_id:{
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: 'users'
    },
    username: {
        type: String,
        default: null,
        trim: true,
    },
    email: {
        type: String,
        default: null,
        trim: true,
    },
    type: {
        type: String,
        default: null,
        trim: true,
    },
    subject: {
        type: String,
        default: null,
        trim: true,
    },
    query: {
        type: String,
        default: null,
        trim: true,
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
    }
});

const contactUs = mongoose.model('contactUs', contactUsSchema);
module.exports = contactUs;
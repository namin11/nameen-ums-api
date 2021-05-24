const mongoose = require('mongoose');
var Schema = mongoose.Schema;

var announcementSchema = new mongoose.Schema({
    title: {
        type: String,
        default: null,
        trim: true,
    },
    category: {
        type: String,
        default: null,
        trim: true,
    },
    description: {
        type: String,
        default: null,
        trim: true,
    },
    created_at: {
        type: Number,
    },
    updated_at: {
        type: Number,
    }
});

const announcement = mongoose.model('announcement', announcementSchema);
module.exports = announcement;
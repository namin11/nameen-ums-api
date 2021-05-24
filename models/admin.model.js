const mongoose = require('mongoose');
var Schema = mongoose.Schema;

var adminSchema = new mongoose.Schema({
    item: {
        type: String,
        default: null,
        trim: true,
    },
    path: {
        type: String,
        default: null,
        trim: true,
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

const admin = mongoose.model('admin', adminSchema);
module.exports = admin;
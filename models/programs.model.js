const mongoose = require('mongoose');
var Schema = mongoose.Schema;

var programsSchema = new mongoose.Schema({
    name: {
        type: String,
        default: null,
        required: true
    },
    fees: {
        type: Number,
        default: 25000,
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

const programs = mongoose.model('programs', programsSchema);
module.exports = programs;
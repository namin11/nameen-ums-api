const mongoose = require('mongoose');
var Schema = mongoose.Schema;

var feesSchema = new mongoose.Schema({
    voucher: {
        type: String,
        default: null,
        trim: true,
        required: true
    },
    narration: {
        type: String,
        default: null,
        required: true
    },
    debit: {
        type: Number,
        default: 10000
    },
    credit: {
        type: Number,
        default: 10000
    },
    created_at: {
        type: Number,
    },
    updated_at: {
        type: Number,
    },
});

const fees = mongoose.model('fees', feesSchema);
module.exports = fees;
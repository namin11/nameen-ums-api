const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
// const _ = require('lodash');
const constants = require('../config/constants');
const dateFormat = require('../helper/dateformat.helper');


const {
    JWT_SECRET
} = require('../keys/keys')

var Schema = mongoose.Schema;

//Define user schema
var userSchema = new Schema({
    register_id: {
        type: String,
        default: null
    },
    email: {
        type: String,
        trim: true,
        lowercase: true,
    },
    profile_pic: {
        type: String,
        default: null
    },
    aadhaar_card: {
        type: String,
        default: null
    },
    first_name: {
        type: String,
        default: null
    },
    last_name: {
        type: String,
        default: null
    },
    father_name: {
        type: String,
        default: null
    },
    mother_name: {
        type: String,
        default: null
    },
    mobile: {
        type: Number,
        default: null
    },
    password: {
        type: String,
        minlength: 6,
    },
    user_type: {
        type: Number, // 1-admin 2-faculty 3-student
        default: 3
    },
    status: {
        type: Number,
        default: constants.STATUS.ACTIVE
    },
    gender: {
        type: String,
        default: null //
    },
    date_of_birth: {
        type: Number,
        default: null
    },
    address: {
        type: String,
        default: null
    },
    country_id: {
        type: Schema.Types.ObjectId,
        ref: 'countries',
        default: null
    },
    state_id: {
        type: Schema.Types.ObjectId,
        ref: 'countries',
        default: null
    },
    city_id: {
        type: Schema.Types.ObjectId,
        ref: 'countries',
        default: null
    },
    tokens: {
        type: String
    },
    reset_password_token: {
        type: String
    },
    program_id: {
        type: Schema.Types.ObjectId,
        ref: 'programs',
        default: null
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

userSchema.index({
    "email": 1
});

//Checking if password is valid
userSchema.methods.validPassword = function (password) {
    console.log("password..", password)
    console.log("this.password..", this.password)
    return bcrypt.compareSync(password, this.password);
};

//Output data to JSON
userSchema.methods.toJSON = function () {
    var user = this;
    var userObject = user.toObject();
    return userObject;
};

//Checking for user credentials
userSchema.statics.findByCredentials = async function ( register_id, password) {

    console.log("register_id..",register_id)

    const user = await User.findOne({
        register_id,
        // $or:[{email: email},{user_name: email}],
        deleted_at: null
    });

    console.log("...userlllll.",user)

    if (!user) {
        return 1
    }

    if (!user.validPassword(password)) {
        return 2
    }

    return user;
}

//Generating auth token
userSchema.methods.generateAuthToken = async function () {
    var user = this;
    var token = await jwt.sign({
        _id: user._id.toString()
    }, JWT_SECRET)
    // user.tokens = user.tokens.concat({
    //     token
    // });
    user.tokens = token
    user.updated_at = await dateFormat.set_current_timestamp();
    await user.save()
    return token
}

//Define user model
var User = mongoose.model('users', userSchema);
module.exports = User;
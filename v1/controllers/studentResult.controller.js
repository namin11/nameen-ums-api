
const {
    sendResponse
} = require('../../services/common.service')
const {
    getAllStudentResult,
    getStudentResultByStudent,
    getStudentResultBySem,
} = require("../services/studentResult.service");
const StudentResult = require('../../models/studentResult.model')
const constants = require('../../config/constants')
const dateFormat = require('../../helper/dateformat.helper');
const User = require('../../models/user.model');

const e = require('express');



exports.getAllStudentResults = async (req, res) => {

    try {

        let {
            limit,
            page,
            sortBy,
            q
        } = req.query


        limit = +limit || constants.LIMIT;
        page = +page || constants.PAGE;

        const sort = {};
        if (sortBy) {
            const parts = sortBy.split(':');
            field = parts[0];
            parts[1] === 'desc' ? value = -1 : value = 1;
        } else {
            field = "created_at",
                value = 1;
        }

        var query = {
            deleted_at: {
                $eq: null
            },
        }
        let total = await StudentResult.countDocuments(query)

        let resultData

        if (limit == -1) {
            resultData = await StudentResult.find(query)
                .sort({
                    [field]: value
                })
                .lean();
        } else {
            resultData = await StudentResult.find(query)
                .sort({
                    [field]: value
                })
                .skip((page - 1) * limit)
                .limit(limit)
                .lean();
        }
        let nameResult = [];
    for(let result of resultData){
      const getStudent = await User.findById(result.student_id)
      if(getStudent)
      nameResult.push({
          ...result,
          first_name:getStudent?.first_name,
          last_name: getStudent?.last_name,
          register_id: getStudent?.register_id,
      })
    }
    console.log();

        let data = {
            rows: nameResult,
            page,
            limit,
            total
        }

        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'STUDENTRESULT.student_result_list_success', data, req.headers.lang);

    } catch (err) {
        console.log("err........", err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}

exports.getStudentResultBySem = async (req, res, next) => {
    try { 
        let data = await getStudentResultBySem(req);
        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'STUDENTRESULT.student_result_fetch_success', data, req.headers.lang);
    } catch (err) {
        console.log(err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}

exports.getStudentResults = async (req, res) => {
    try {
        let data = await getStudentResultByStudent(req.params.student_id);
        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'STUDENTRESULT.student_result_fetch_success', data, req.headers.lang);
    } catch (err) {
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang);
    }
};

exports.createStudentResult = async (req, res, next) => {
    try {
        let reqBody = req.body
        reqBody.faculty_id = req.user._id,
        reqBody.created_at = await dateFormat.set_current_timestamp();
        reqBody.updated_at = await dateFormat.set_current_timestamp();
        let studentResult = new StudentResult(reqBody)
        let data = await studentResult.save()
        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'STUDENTRESULT.create_student_result_success', data, req.headers.lang);

    } catch (err) {
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}

exports.editStudentResult = async (req, res, next) => {
    try {
        const reqBody = req.body;
        console.log(req.body);
        reqBody.updated_at = await dateFormat.set_current_timestamp();
        await StudentResult.findByIdAndUpdate({
            _id: reqBody._id
        }, reqBody)

        let resultData = await StudentResult.findById(reqBody._id).lean()
        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'STUDENTRESULT.student_update_success', resultData, req.headers.lang);

    } catch (err) {
        console.log(err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}

exports.deleteStudentResult = async (req, res, next) => {
    try {
        const resultId = req.params._id
        const resultDetails = await StudentResult.findById(resultId).lean()
        if (resultDetails) {
            await StudentResult.findByIdAndDelete(resultId)
            return sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'STUDENTRESULT.result_deleted', {}, req.headers.lang);
        } else {
            return sendResponse(res, constants.WEB_STATUS_CODE.BAD_REQUEST, constants.STATUS_CODE.FAIL, 'STUDENTRESULT.result_not_found', {}, req.headers.lang);
        }

    } catch (err) {
        console.log(err)
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang)
    }
}
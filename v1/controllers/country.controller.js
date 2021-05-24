const {
    sendResponse
} = require('../../services/common.service')
const constants = require('../../config/constants')


const {
    getAllCountries,
    getStatesOfCountry,
    getCitiesOfState
} = require("../services/country.service");
const e = require('express');

exports.getCountyList = async (req, res) => {
    try {
        let data = await getAllCountries();

        console.log("data...", data.length)

        sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'COUNTRY.county_list_fetch_success', data, req.headers.lang);
    } catch (err) {
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang);
    }
};
exports.getStatesOfCountry = async (req, res) => {
    try {
        const countryId = req.params.country_id
        const data = await getStatesOfCountry(countryId);

        if (data) {
            sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'COUNTRY.state_list_fetch_success', data, req.headers.lang);
        } else {
            sendResponse(res, constants.WEB_STATUS_CODE.BAD_REQUEST, constants.STATUS_CODE.FAIL, 'COUNTRY.state_list_not_found', data, req.headers.lang);
        }

    } catch (err) {
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang);
    }
};

exports.getCitiesOfState = async (req, res) => {
    try {
        const stateId = req.params.state_id
        const data = await getCitiesOfState(stateId);

        if (data.length > 0) {
            sendResponse(res, constants.WEB_STATUS_CODE.OK, constants.STATUS_CODE.SUCCESS, 'COUNTRY.city_list_fetch_success', data, req.headers.lang);
        } else {
            sendResponse(res, constants.WEB_STATUS_CODE.BAD_REQUEST, constants.STATUS_CODE.FAIL, 'COUNTRY.city_list_not_found', data, req.headers.lang);
        }
    } catch (err) {
        sendResponse(res, constants.WEB_STATUS_CODE.SERVER_ERROR, constants.STATUS_CODE.FAIL, 'GENERAL.general_error_content', err.message, req.headers.lang);
    }
};

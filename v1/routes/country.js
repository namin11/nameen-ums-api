var express = require('express');
var router = express.Router();

const {
    getCountyList,
    getStatesOfCountry,
    getCitiesOfState 
} = require('../controllers/country.controller')


router.get('/country-list', getCountyList)
router.get('/states-of-country/:country_id', getStatesOfCountry);
router.get('/cities-of-state/:state_id', getCitiesOfState);

// router.get('/states-of-country', getStatesOfCountry);
// router.get('/cities-of-state', getCitiesOfState);


module.exports = router;

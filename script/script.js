// const County = require("../models/country.model");
// const CountyData = require("./countryJSON")

const EmailFormat = require('../models/emailTemplate.model')
const emailTemplate = require('./emailTemplate.script')


async function getAllCountriesData() {

    try {
        // const countryData = await County.findOne({})
        // if (!countryData) {
        //     const countryData = await County.insertMany(CountyData)
        // }

        let emailTemplates = await EmailFormat.findOne({});
        if (!emailTemplates) {
            await EmailFormat.insertMany(emailTemplate.EMAIL_TEMPLATES);
        }

    } catch (err) {
        throw err
    }
}

getAllCountriesData()





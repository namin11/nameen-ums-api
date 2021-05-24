
const Country = require('../../models/country.model')
// const NewCountry = require('../../models/newCountry.model')



const { ObjectId } = require('mongoose').Types;


exports.getAllCountries = async () => {
  try {
    const data = await Country.aggregate([
      {
        $project: {
          name: 1,
          alpha3Code: 1
        }
      },
      {
        $sort: {
          name: 1
        }
      },
    ]);

    return data;
  } catch (error) {
    throw error;
  }
};


exports.getStatesOfCountry = async countryId => {
  try {
    console.log("countryId......", countryId)
    const data = await Country.findById( countryId , { 'states.name': 1, 'states._id': 1, _id: 0 }).lean();
   
    if (data){
      return data.states;
    }
    return data;
  } catch (error) {
    throw error;
  }
};

exports.getCitiesOfState = async stateId => {
  try {

    console.log("stateId........", stateId)
    const data = await Country.aggregate([
      {
        $unwind: '$states'
      },
      {
        $match: {
          'states._id': ObjectId(stateId)
        }
      },
      {
        $project: {
          'states.cities': 1,
          _id: 0
        }
      },
      {
        $unwind: '$states'
      },
      {
        $unwind: '$states.cities'
      },
      {
        $replaceRoot: { newRoot: '$states.cities' }
      },
      {
        $project: {
          'name': 1,
          '_id': 1
        }
      }
    ]);
    return data;
  } catch (error) {
    throw error;
  }
};
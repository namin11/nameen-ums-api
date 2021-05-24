const mongoose = require("mongoose");

const citySchema = new mongoose.Schema({
  name: { type: String, required: true }
});

const stateSchema = new mongoose.Schema({
  name: { type: String, required: true },
  cities: [citySchema]
});

const CountrySchema = new mongoose.Schema({
  flag: { type: String },
  name: { type: String },
  alpha2Code: { type: String },
  alpha3Code: { type: String },
  callingCodes: [String],
  latlng: [Number],
  timezones: [String],
  states: [stateSchema]
});



CountrySchema.index({ alpha3Code: 1 ,'states.name': 1 , 'states.cities.name': 1  });

var NewCountry = mongoose.model('newCountry', CountrySchema);
module.exports = NewCountry;
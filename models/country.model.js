const mongoose = require("mongoose");

// const citySchema = new mongoose.Schema({
//   name: { type: String, required: true }
// });

// const stateSchema = new mongoose.Schema({
//   name: { type: String, required: true },
//   cities: [citySchema]
// });

// const CountrySchema = new mongoose.Schema({
//   flag: { type: String },
//   name: { type: String },
//   alpha2Code: { type: String },
//   alpha3Code: { type: String },
//   callingCodes: [String],
//   latlng: [Number],
//   timezones: [String],
//   states: [stateSchema]
// });

const citySchema = new mongoose.Schema({
  id: { type: Number},
  latitude: { type: String},
  longitude: {type:String},
  name: { type: String, required: true }
});

const stateSchema = new mongoose.Schema({
  id: { type: Number},
  state_code: { type: String},
  name: { type: String, required: true },
  cities: [citySchema]
});

const CountrySchema = new mongoose.Schema({
  id: { type: Number},
  flag: { type: String },
  name: { type: String },
  iso2: { type: String },
  iso3: { type: String },
  phone_code: [String],
  capital: { type: String },
  currency: { type: String },
  states: [stateSchema]
}); 

CountrySchema.index({ alpha3Code: 1 ,'states.name': 1 , 'states.cities.name': 1  });

var Country = mongoose.model('country', CountrySchema);
module.exports = Country;
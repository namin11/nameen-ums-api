const moment = require('moment');
const momentTZ = require('moment-timezone');

//set current timestamp
exports.set_current_timestamp = function(){
    return moment().format("X");
}

//convert date to timestamp
exports.getDateFormatFromTimeStamp = function(dt){
    return moment.unix(dt).format("MM/DD/YYYY")    
}

//add time to current timestamp
exports.add_time_to_current_timestamp = function(number,timeformat){
    return moment().add(number,timeformat).format("X");
}

//convert YYYYMMDD date format to timestamp
exports.convert_date_to_timestamp = function(date){
    return moment(date, "YYYYMMDD").format("X")
}

//convert timestamp to date and time for america
exports.getDateAndTimeFormatFromTimeStampForUSA = function(dt){
    return momentTZ.unix(dt).tz("America/New_York").format("MM/DD/YYYY HH:mm:ss")    
}

//set current date
exports.set_current_date = function(){
    return moment().format("MMDDYYYYHHmmss");
}
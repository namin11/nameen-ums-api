
const constants = require('../config/constants');
var _ = require('lodash');


exports.sendResponse = (res, statusCode, status, message, data, lang= 'en') => {
    try{
            
        appLanguageList = constants.APP_LANGUAGE;    
        const msg = ((appLanguageList.indexOf(lang) != -1)) ? require(`../lang/${lang}/message`) : require(`../lang/en/message`)
    
        let obj = message.split(".");
        keyName = obj[0];
        subKey = obj[1];
    
        const resMessage = msg[keyName][subKey];
    
        res.writeHead(statusCode, {'Content-Type': 'application/json'});
        res.write(JSON.stringify({
            "status": status,
            "message": resMessage,
            "data": data
        }));
        res.end();

    } catch (err) {
        throw err
    }
}

exports.responseIn = function(message, lang='en'){
    appLanguageList = constants.APP_LANGUAGE;    
    const msg = ((appLanguageList.indexOf(lang) != -1)) ? require(`../lang/${lang}/validationMessage`) : require(`../lang/en/validationMessage`)
    
    let obj = message.split(".");
    keyName = obj[0];
    subKey = obj[1];

    console.log("keyName.....",keyName)
    console.log("subKey.....",subKey)

    return msg[keyName][subKey];
}

exports.responseMessage = function(message, lang='en'){
    appLanguageList = constants.APP_LANGUAGE;    
    const msg = ((appLanguageList.indexOf(lang) != -1)) ? require(`../lang/${lang}/message`) : require(`../lang/en/message`)
    
    let obj = message.split(".");
    keyName = obj[0];
    subKey = obj[1];

    console.log("keyName.....",keyName)
    console.log("subKey.....",subKey)

    return msg[keyName][subKey];
}

exports.replaceStringWithObjectData = (str, object) => {
	if(!_.isEmpty(object)){
		stringStartSymbol = (typeof(constants.ENCRYPT_STRING.START_SYMBOL)===undefined) ? '{!{' : constants.ENCRYPT_STRING.START_SYMBOL

		stringEndSymbol = (typeof(constants.ENCRYPT_STRING.END_SYMBOL)===undefined) ? '}!}' : constants.ENCRYPT_STRING.END_SYMBOL

		for (let data in object) {

			msg = stringStartSymbol+data+stringEndSymbol
			str = str.replace(new RegExp(msg, 'g'), object[data])  //for replace all occurance
            //str = str.replace(msg, object[data])
		}
		return str;
	}
	return "";
}


exports.sendResponseValidation = (res, statusCode, status, message, data, lang= 'en') => {
    try{
            
        appLanguageList = constants.APP_LANGUAGE;    
        const msg = ((appLanguageList.indexOf(lang) != -1)) ? require(`../lang/${lang}/validationMessage`) : require(`../lang/en/validationMessage`)
    
        let obj = message.split(".");
        keyName = obj[0];
        subKey = obj[1];
    
        const resMessage = msg[keyName][subKey];
    
        res.writeHead(statusCode, {'Content-Type': 'application/json'});
        res.write(JSON.stringify({
            "status": status,
            "message": resMessage,
            "data": data
        }));
        res.end();

    } catch (err) {
        throw err
    }
}


exports.removeDuplicates = inputArray => {
    const ids = [];
    return inputArray.reduce((sum, element) => {
       if(!ids.includes(element.toString())){
           sum.push(element);
           ids.push(element.toString());
       }
       return sum;
    }, []);
};

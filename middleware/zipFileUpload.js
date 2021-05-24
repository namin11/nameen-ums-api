const multer = require('multer');
const path = require('path');

const constants = require('../config/constants');
// const Lang = require('../../helper/response.helper');

var fileStorage = multer.diskStorage({
    
    destination: (req, file, cb) => {
        fileImgPath = constants.PATH.CMS_UPLOAD_PATH;
     cb(null, fileImgPath)
    },
     filename: (req, file, cb) => {
        if(!file.originalname.match(/\.(zip)$/i)){
            console.log("wwwww")
        //    return cb(new Error(Lang.responseIn("USER.VALID_ZIP_FILE", req.headers.lang)));
        } else {
            console.log("wwwww22222")
        }
        var ext = path.extname(file.originalname);


      cb(null, file.fieldname + '-' + Date.now()+ext)
    },
    limits: {
        fileSize: 1000000
    }
});
var zipUpload = multer({storage: fileStorage}).single('zipFile');
module.exports = zipUpload


// var storage = multer.diskStorage({
//     destination: function (req, file, cb) {
//       cb(null, '/tmp/my-uploads')
//     },
//     filename: function (req, file, cb) {
//       const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9)
//       cb(null, file.fieldname + '-' + uniqueSuffix)
//     }
//   })
  
//   var upload = multer({ storage: storage })
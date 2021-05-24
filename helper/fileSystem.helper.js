const fs = require('fs');
const _ = require('lodash');

const constants = require('../config/constants');

let getListOfFilesOrFolderOfGivenPath = async(directoryPath, FS_TYPE) => {
    // console.log("directoryPath", directoryPath);
    let filesArray = [];
    let filesList = fs.readdirSync(directoryPath);

    for(let i=0; i < filesList.length; i++){
        let fileNames = await new Promise((resolve, reject) => {
            fs.stat(directoryPath + `/${filesList[i]}`, function(err, stats) {
                if(FS_TYPE == constants.FS_TYPES.DIR && stats.isDirectory() == true){
                    resolve(filesList[i]);
                }else if(FS_TYPE == constants.FS_TYPES.FILE && stats.isFile() == true){
                    resolve(filesList[i]);
                }else{
                    resolve(null);
                }
            })
        })

        if(fileNames){
            filesArray.push(fileNames);
        }
    }

    return filesArray;
}

let deleteDirData = async(dir) => {
    return new Promise((resolve, reject) => {
        fs.rmdirSync(dir, { recursive: true }, (err) => {
            if (err) {
                resolve(null)     
            }
            console.log(`${dir} is deleted!`);
            resolve(true)        
        });
    })
}

module.exports = {
    getListOfFilesOrFolderOfGivenPath,
    deleteDirData
}
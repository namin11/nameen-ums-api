const fs = require('fs');
const archiver = require('archiver');
const AdmZip = require('adm-zip');
const constants = require('../config/constants');
// const dateFormat = require('../helper/dateFormate.helper');
const fsHelper = require('../helper/fileSystem.helper');

let compressData = async (sourceDirPath, zipDestinationPath) => {
    let compressionResult = [];
    console.log("sourceDirPath", sourceDirPath);
    console.log("zipDestinationPath", zipDestinationPath);
    
    let filesList = await fsHelper.getListOfFilesOrFolderOfGivenPath(sourceDirPath, constants.FS_TYPES.FILE);
    let directoryList = await fsHelper.getListOfFilesOrFolderOfGivenPath(sourceDirPath, constants.FS_TYPES.DIR);
    console.log("filesList", filesList);
    console.log("directoryList", directoryList);
    
    if(filesList.length > 0 || directoryList.length > 0){
        compressionResult = await new Promise((resolve, reject) => {
            let output = fs.createWriteStream(zipDestinationPath);
            let archive = archiver('zip');  
            
            output.on('close', function() {
                // console.log(archive.pointer() + ' total bytes');
                resolve(true);
            });
            archive.on('error', function(err){
                resolve(null);
            });
            archive.pipe(output);

            for(let f = 0; f < filesList.length; f++){
                var path = sourceDirPath+'/'+filesList[f];
                archive.append(getStream(path), { name: filesList[f]});
            }
            for(let d = 0; d < directoryList.length; d++){
                var path = sourceDirPath+'/'+directoryList[d];
                archive.directory(path, directoryList[d]);
            }

            archive.finalize();
        });
    }
    return compressionResult;
}

let extractDataWithAdmZip = async(sourcePath, destinationPath) => {
    let zip = new AdmZip(sourcePath);
    let zipEntries = zip.getEntries();
    zip.extractAllTo(destinationPath, true);
}

let getStream = (filePath) => {
    return fs.readFileSync(filePath);
}

module.exports = {
    compressData,
    extractDataWithAdmZip
}
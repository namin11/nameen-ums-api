const {
  ObjectId
} = require('mongoose').Types;


const User = require("../../models/user.model")

exports.getUser = async (idOrEmail, fieldName = '_id') => {
  const data = await User.findOne({
    [fieldName]: `${idOrEmail}`
  });
  return data;
};

exports.getUserDetails = async (userId, stateId, cityId) => {

  console.log("(userId, stateId, cityId)", userId, stateId, cityId)

  let data;

  if (cityId && (stateId != null)) {

    console.log("111111")
    data = await User.aggregate([{
        $match: {
          _id: userId
        }
      },
      {
        $lookup: {
          from: "newcountries",
          localField: "countryId",
          foreignField: "_id",
          as: "countryData"
        }
      },
      {
        $unwind: '$countryData',
      },
      {
        $unwind: '$countryData.states',
      },
      {
        $match: {
          'countryData.states._id': ObjectId(stateId)
        }
      },
      {
        $unwind: '$countryData.states.cities',
      },
      {
        $match: {
          'countryData.states.cities._id': ObjectId(cityId)
        }
      },
      {
        $addFields: {
          "country._id": "$countryData._id",
          "country.name": "$countryData.name",
          "state._id": "$countryData.states._id",
          "state.name": "$countryData.states.name",
          "city._id": "$countryData.states.cities._id",
          "city.name": "$countryData.states.cities.name",
        }
      },
      {
        $project: {
          "countryData": 0

        }
      }
    ])

  } else if (stateId != null) {
    console.log("333333")


    data = await User.aggregate([{
        $match: {
          _id: userId
        }
      },
      {
        $lookup: {
          from: "newcountries",
          localField: "countryId",
          foreignField: "_id",
          as: "countryData"
        }
      },
      {
        $unwind: '$countryData',
      },
      {
        $unwind: '$countryData.states',
      },
      {
        $match: {
          'countryData.states._id': ObjectId(stateId)
        }
      },
      // {
      //   $unwind: '$countryData.states.cities',
      // },
      // {
      //   $match: {
      //     'countryData.states.cities._id': ObjectId(cityId)
      //   }
      // },
      {
        $addFields: {
          "country._id": "$countryData._id",
          "country.name": "$countryData.name",
          "state._id": "$countryData.states._id",
          "state.name": "$countryData.states.name",
          // "city._id": "$countryData.states.cities._id",
          // "city.name": "$countryData.states.cities.name",
        }
      },
      {
        $project: {
          "countryData": 0

        }
      }
    ])


  } else {



    console.log("2222222")
    data = await User.aggregate([{
        $match: {
          _id: userId
        }
      },
      {
        $lookup: {
          from: "newcountries",
          localField: "countryId",
          foreignField: "_id",
          as: "countryData"
        }
      },
      {
        $unwind: '$countryData',
      },
      {
        $addFields: {
          "country._id": "$countryData._id",
          "country.name": "$countryData.name"
        }
      },
      {
        $project: {
          "countryData": 0

        }
      }
    ])

  }

  console.log("......................................", data)

  return data[0]
};

exports.Usersave = data => new User(data).save();

exports.deleteUser = async userId => {
  try {
    const deleteData = await User.findByIdAndDelete(userId)
    return deleteData
  } catch (err) {
    throw err
  }
}

exports.userVerifyToken = async (userId, emailVerificationToken) => {
  try {
    const {
      nModified
    } = await User.update({
      _id: userId,
      tempTokens: emailVerificationToken
    }, {
      $set: {
        verify_token: true,
        tempTokens: ''
      }
    }, {
      runValidators: true
    })

    return nModified
  } catch (err) {
    throw err
  }
}

exports.userVerifyEmail = async (userId, emailVerificationToken, email) => {
  try {
    const {
      nModified
    } = await User.update({
      _id: userId,
      tempTokens: emailVerificationToken
    }, {
      $set: {
        is_email_changed: false,
        email: email,
        tempTokens: ''
      }
    }, {
      runValidators: true
    })

    return nModified
  } catch (err) {
    throw err
  }
}



exports.updateUser = async (conditionData, updateData) => {
  try {
    const {
      nModified
    } = await User.update(
      conditionData, {
        $set: updateData
      }, {
        runValidators: true
      }
    )

    return nModified
  } catch (err) {
    throw err
  }
}


exports.updateUserById = async (userId, updateData) => {
  try {
    const {
      nModified
    } = await User.findByIdAndUpdate(
      userId, {
        $set: updateData
      }, {
        runValidators: true
      }
    )

    return nModified
  } catch (err) {
    throw err
  }
}
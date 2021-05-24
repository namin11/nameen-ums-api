
const Workout = require('../../models/workout.model')
const {
    ObjectId
} = require('mongoose').Types;

const ProgramWorkouts = require('../../models/programWorkouts.model');
const Programs = require('../../models/programs.model');



exports.getWorkoutSuggestedFgm_Fga = async workoutIds => {
    try {
        
        console.log("workoutIdsArr.......",workoutIds)

        const data = await Workout.aggregate([{
                $match: {
                    _id: {
                        $in: workoutIds
                    }
                }
            },
            // {
            //     $group: {
            //         _id: {},
            //         suggested_FGM: {
            //             $sum: "$suggested_FGM"
            //         },
            //         suggested_FGA: {
            //             $sum: "$suggested_FGA"
            //         },
            //         number_of_workout: {
            //             $sum: 1
            //         }
            //     }
            // }
        ]);

        let total = {
            suggested_FGM: 0,
            suggested_FGA: 0
        }
        workoutIds.forEach(e => {

            let findData = data.find(element => (element._id).toString() == e.toString())

            total.suggested_FGM += findData.suggested_FGM
            total.suggested_FGA += findData.suggested_FGA

        });

        return total;

        return data;
    } catch (error) {
        console.log("error..", error)
        throw error;
    }
};

exports.getProgramWorkouts = async programId => {
    try {

        let program_Objectid = ObjectId(programId)
        const data = await ProgramWorkouts.aggregate([
            {
                $match:
                 {
                    program_id: program_Objectid
                }
            },
            {
                $lookup: {
                    from: "workouts",
                    localField: "workout_id",
                    foreignField: "_id",
                    as: "workout_data"
                }
            },
            {
                $unwind: '$workout_data',
            },
        ])

        return data

    } catch (error) {
        console.log("error..", error)
        throw error;
    }
};


// exports.updateProgramOrder = async (reqOrder) => {
//     try {
//         let totalProgram = await Programs.countDocuments({})
//         let updateArr = []

//         for (let order = reqOrder; order <= totalProgram; order++) {

//             let findProgram = await Programs.findOne(
//                 { order: order }
//              )

//             if (findProgram){
//                 findProgram.order = findProgram.order + 1
//                 updateArr.push(findProgram)
//             } else {
//                 break;
//             }

//         }
//         for (let i = 0; i < updateArr.length; i++) {
//             await Programs.findByIdAndUpdate(
//                 updateArr[i]._id, { order: updateArr[i].order }
//              )
//         }

//         return 1
        
//     } catch (error) {
//         console.log("error..", error)
//         throw error;
//     }
// };

exports.updateProgramOrder = async (reqOrder) => {
    try {
        console.time("Time this");

        let totalProgram = await Programs.find({
            order: {
                $gte: reqOrder
            }
        }).lean()
        totalProgram.sort((a, b) => a.order - b.order);

        let updateArr = []
        for (let i = 0; i < totalProgram.length; i++) {
            if (i == 0 || (totalProgram[i].order - totalProgram[i - 1].order == 1)) {
                let programData = Programs.findByIdAndUpdate(totalProgram[i]._id, {
                    'order': totalProgram[i].order + 1
                })
                updateArr.push(programData)
            } else {
                break;
            }
        }
        await Promise.all(updateArr)

        console.timeEnd("Time this");
        return 1

    } catch (error) {
        console.log("error..", error)
        throw error;
    }
};
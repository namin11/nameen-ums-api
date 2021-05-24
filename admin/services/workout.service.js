const {
    ObjectId
} = require('mongoose').Types;
const Drills = require('../../models/drill.model');
const WorkoutDrills = require('../../models/workoutDrills.model');
const Workouts = require('../../models/workout.model');



exports.getDrillSuggestedFgm_Fga = async drillIds => {
    try {

        let data = await Drills.aggregate([{
                $match: {
                    _id: {
                        $in: drillIds
                    }
                }
            },
            // {
            //     $group: {
            //         _id: {},
            //         total_sugg_int_FGA: {
            //             $sum: "$total_sugg_int_FGA"
            //         },
            //         total_sugg_beg_FGA: {
            //             $sum: "$total_sugg_beg_FGA"
            //         },
            //         total_sugg_adv_FGM: {
            //             $sum: "$total_sugg_adv_FGM"
            //         },
            //         number_of_drill: {
            //             $sum: 1
            //         }
            //     }
            // }
        ]);

        console.log("data.....", data)


        let total = {
            total_sugg_int_FGA: 0,
            total_sugg_beg_FGA: 0,
            total_sugg_adv_FGM: 0
        }
        drillIds.forEach(e => {

            let findData = data.find(element => (element._id).toString() == e.toString())

            total.total_sugg_int_FGA += findData.total_sugg_int_FGA
            total.total_sugg_beg_FGA += findData.total_sugg_beg_FGA
            total.total_sugg_adv_FGM += findData.total_sugg_adv_FGM
        });

        return total;
    } catch (error) {
        console.log("error..", error)
        throw error;
    }
};

exports.getWorkoutDrills = async workoutId => {
    try {

        let workout_Objectid = ObjectId(workoutId)
        const data = await WorkoutDrills.aggregate([{
                $match: {
                    workout_id: workout_Objectid
                }
            },
            {
                $lookup: {
                    from: "drills",
                    localField: "drill_id",
                    foreignField: "_id",
                    as: "drills_data"
                }
            },
            {
                $unwind: '$drills_data',
            },
        ])

        return data

    } catch (error) {
        console.log("error..", error)
        throw error;
    }
};


exports.changeNumberOfUse = async (drillIds, status) => {
    try {
        for (let index = 0; index < drillIds.length; index++) {
            await Drills.findByIdAndUpdate(drillIds[index], {
                $inc: {
                    number_of_use_drill: status
                }
            })
        }
        return 1

    } catch (error) {
        console.log("error..", error)
        throw error;
    }
};

// exports.updateWorkoutOrder = async (reqOrder) => {
//     try {
//         let totalWorkout = await Workouts.countDocuments({})
//         let updateArr = []

//         console.time("Time this");


//         for (let order = reqOrder; order <= totalWorkout; order++) {

//             let findWorkout = await Workouts.findOne(
//                 { order: order }
//              )

//             if (findWorkout){
//                 findWorkout.order = findWorkout.order + 1
//                 updateArr.push(findWorkout)
//             } else {
//                 break;
//             }

//         }

//         console.log("updateArr...",updateArr.length)


//         for (let i = 0; i < updateArr.length; i++) {
//             await Workouts.findByIdAndUpdate(
//                 updateArr[i]._id, { order: updateArr[i].order }
//              )
//         }

//         console.timeEnd("Time this");


//         return 1

//     } catch (error) {
//         console.log("error..", error)
//         throw error;
//     }
// };


// exports.updateWorkoutOrder = async (reqOrder) => {
//     try {
//         let totalWorkout = await Workouts.countDocuments({})
//         let updateArr = []

//                 console.time("Time this");


//         for (let order = reqOrder; order <= totalWorkout; order++) {

//             let findWorkout = await Workouts.findOne(
//                 { order: order }
//              )

//             if (findWorkout){
//                 // findWorkout.order = findWorkout.order + 1
//                 let a = Workouts.findByIdAndUpdate( findWorkout._id, { order: findWorkout.order + 1 })
//                 updateArr.push(a)
//             } else {
//                 break;
//             }

//         }

//         const aa = await Promise.all(updateArr)

//         console.timeEnd("Time this");

//         return 1

//     } catch (error) {
//         console.log("error..", error)
//         throw error;
//     }
// };


exports.updateWorkoutOrder = async (reqOrder) => {
    try {
        console.time("Time this");

        let totalWorkout = await Workouts.find({
            order: {
                $gte: reqOrder
            }
        }).lean()
        totalWorkout.sort((a, b) => a.order - b.order);

        let updateArr = []
        for (let i = 0; i < totalWorkout.length; i++) {
            if (i == 0 || (totalWorkout[i].order - totalWorkout[i - 1].order == 1)) {
                let workoutData = Workouts.findByIdAndUpdate(totalWorkout[i]._id, {
                    'order': totalWorkout[i].order + 1
                })
                updateArr.push(workoutData)
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
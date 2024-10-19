// Imports
const { Schema, model } = require("mongoose");

// Schema
const followerSchema = new Schema({
    follower: {
        type: Schema.Types.ObjectId,
        ref: 'User',
    },
    followee: {
        type: Schema.Types.ObjectId,
        ref: 'User',
    }
}, {
    timestamps: true,
})

// Model
const Follower = model('Follower', followerSchema);

// Exports
module.exports = {Follower};
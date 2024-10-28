// Imports
const { Schema, model } = require("mongoose");

// Schema
const tweetSchema = new Schema({
    content: {
        type: String,
    },
    author: {
        type: Schema.Types.ObjectId,
        ref: 'User',
    },
    likeCount: {
        type: Number,
        default: 0
    }
}, {
    timestamps: true,
});

// Model
const Tweet = model("Tweet", tweetSchema);

// Exports
module.exports = {Tweet};

// Imports
const { Schema, model } = require("mongoose");

// Schema
const userSchema = new Schema({
    userName: {
        type: String,
    },
    firstName: {
        type: String,
    },
    lastName: {
        type: String,
    },
    email: {
        type: String,
    },
    password: {
        type: String,
    },
    tokenVersion: {
        type: Number,
        default: 0
    }
}, {
    timestamps: true,
}); 

// Model
const User = model("User", userSchema);

// Exports
module.exports = {User};
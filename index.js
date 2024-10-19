// Imports
const express = require("express");
require("dotenv").config();
const mongoose = require("mongoose");
const { sign, verify, decode } = require("jsonwebtoken");
const { json, urlencoded } = require("body-parser");
const { User } = require("./models/user.model");
const { genSalt, hash, compare } = require("bcrypt");
const { authenticateToken, isLoggedOut } = require("./middlewares/auth.middleware");

// Declarations
const app = express();

console.log("process host = ", process.env.HOST);
console.log("process port = ", process.env.PORT);
console.log("process database connection string = ", process.env.DB_CONNECTION_STRING);
console.log("process secret key = ", process.env.SECRET_KEY);

// server start
(async () => {
    try {
        let db = await mongoose.connect(`${process.env.DB_CONNECTION_STRING}/${process.env.DB_NAME}`);
        if(db.connection.db.databaseName === "tweeter") {
        console.log("database connected");
        app.listen(process.env.PORT, process.env.HOST, () => {
            console.log("server started");
        });
        } else {
            console.log("database not connected");
        }
    } catch(err) {
        console.log({...err});
    }
})();

// Middlewares
app.use(json());
app.use(urlencoded());
app.post("/api/v1/auth/register", async (req, res, next) => {
    const { firstName, lastName, userName, email, password } = req.body;
    let foundUser = null;
    let newUser = null;
    let accessToken = null;
    let refreshToken = null;
    let salt = null;
    let saltRounds = 10;
    let hashPassword = null;
    try {
        foundUser = await User.findOne({email: email, userName: userName}).lean();
        console.log(foundUser);
        if(foundUser) return res.status(403).send({message: "user already exist"});
        
        salt = await genSalt(saltRounds);
        console.log("salt = ", salt);
        
        hashPassword = await hash(password, salt);
        console.log("password = ", hashPassword);

        newUser = new User({
            firstName,
            lastName,
            userName,
            email,
            password: hashPassword,
            tokenVersion: 0
        })
        await newUser.save();

        console.log("new user = ", newUser);

        accessToken = sign(
            {
                id: newUser._id, 
                role: "user",
                tokenVersion: newUser.tokenVersion
            }, 
            process.env.SECRET_KEY, 
            {
                expiresIn: "10m"
            });

        refreshToken = sign(
            {
                id: newUser._id,
                role: "user"
            },
            process.env.SECRET_KEY,
            {
                expiresIn: "2d"
            });
        res.status(200).send({message: "success", accessToken, refreshToken});
    } catch(err) {
        res.send(err);
    }
});
app.post("/api/v1/auth/login", async (req, res, next) => {
    const { userName, email, password } = req.body;
    let foundUser = null;
    let encryptedPassword = null;
    let accessToken = null;
    let refreshToken = null;
    try{
        foundUser = await User.findOne({email: email, userName: userName});
        if(!foundUser) {
            return res.send({message: "invalid credentials"});
        }

        encryptedPassword = foundUser.password;
        
        compare(password, encryptedPassword)
        .then(async (isValidPassword) => {
            if(isValidPassword) {
                accessToken = sign(
                    {
                        id: foundUser._id, 
                        role: 'user',
                        tokenVersion: 0 
                    }, 
                    process.env.SECRET_KEY, 
                    {expiresIn: "1m"});
                refreshToken = sign(
                    {
                        id: foundUser._id,
                        role: 'user'
                    }, 
                    process.env.SECRET_KEY, 
                    {expiresIn: "2m"});

                    foundUser.tokenVersion = 0;
                    await foundUser.save();

                return res.status(200).send({
                    message: "success", 
                    accessToken: accessToken,
                    refreshToken: refreshToken
                });
            } else {
                return res.status(403).send({message: "password invalid"});
            }
        })
    } catch(err) {
        return res.send(err);
    }
});
app.post("/api/v1/auth/refresh-token", async (req, res, next) => {
    let currentTimeInSeconds = 0;
    let {refreshToken} = req.body;
    let newAccessToken = null;
    let newRefreshToken = null;
    if(!refreshToken) return res.send({message: "Token Empty"});  

    // Refresh Token Authentication
    // Signature Validation
    let payload = verify(refreshToken, process.env.SECRET_KEY);
    console.log("payload = ", payload);
    if(!payload) return res.send({message: "Token Invalid"});

    // Refresh Token Expiry Validation
    currentTimeInSeconds = Number((new Date().getTime()/1000).toFixed(0));
    if(currentTimeInSeconds > payload.expiresIn) return res.status(403).send({message: "Token Expired"});

    // If Token Valid and Not Expired
    // Generate new access token
    newAccessToken = sign(
        {
            id: payload.id,
            role: payload.role,
        },
        process.env.SECRET_KEY,
        {
            expiresIn: "10m",
        }
    )

    // Generate new refresh token
    newRefreshToken = sign(
        {
            id: payload.id,
            role: payload.role
        },
        process.env.SECRET_KEY,
        {
            expiresIn: "2d",
        }
    )
    
    res.send({accessToken: newAccessToken, refreshToken: newRefreshToken});
});
app.post("/api/v1/auth/logout", async (req, res, next) => {
    // logout algo
    // token versioning
    // decode the access token and extract payload
    // find user from database using user id from payload
    // increment the token version of the found user
    // then update the database with new token version value
    let accessToken = req.get("Authorization").split(" ")[1];
    let foundUser = null;
    let id =  null; 
    try {
        id = decode(accessToken).id;
        console.log("user id = ", id);
        console.log("access token = ", accessToken);
        foundUser = await User.findOne({_id: id});

        foundUser.tokenVersion = foundUser.tokenVersion + 1;
        await foundUser.save();
        return res.status(200).send({message:"User logged out"});
    } catch(err) {
        return res.status(500).send(err);
    }
});
app.post("/api/v1/auth/forgot-password", async(req, res, next) => {

});
app.post("/api/v1/auth/change-password", async (req, res, next) => {

});
app.post("/api/v1/user/post-tweet", authenticateToken, isLoggedOut, (req, res, next) => {
    console.log("protected resource");
    res.send("protected resource");
});
app.post("api/v1/user/create-follow", authenticateToken, isLoggedOut, (req, res, next) => {
    console.log("protected resource");
    res.send("protected resource");
})
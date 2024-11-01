// Imports
const express = require("express");
require("dotenv").config();
const mongoose = require("mongoose");
const { sign, verify, decode } = require("jsonwebtoken");
const { json, urlencoded } = require("body-parser");
const { User } = require("./models/user.model");
const { Tweet } = require("./models/tweet.model");
const { genSalt, hash, compare } = require("bcrypt");
const { verifyAccessToken, verifyLogin } = require("./middlewares/authenticate.middleware");
const { verifyRole } = require("./middlewares/authorize.middleware");
const nodemailer = require("nodemailer");
const { roles } = require("./config/roles.config");

// Declarations
const app = express();

// server start
(async () => {
    try {
        let db = await mongoose.connect(`${process.env.DB_CONNECTION_STRING}/${process.env.DB_NAME}`);
        if(db.connection.db.databaseName === "tweeter") {
        console.log("database connected");
        app.listen(process.env.PORT, process.env.HOST, () => {
            console.log("server started listening");
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

// Authorization and Authentication Management
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
                role: roles.user,
                tokenVersion: newUser.tokenVersion
            }, 
            process.env.SECRET_KEY, 
            {
                expiresIn: "10m"
            });

        refreshToken = sign(
            {
                id: newUser._id,
                role: roles.user,
            },
            process.env.SECRET_KEY,
            {
                expiresIn: "2d"
            });

        console.log
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
                        role: roles.user,
                        tokenVersion: 0 
                    }, 
                    process.env.SECRET_KEY, 
                    {expiresIn: "10m"});
                refreshToken = sign(
                    {
                        id: foundUser._id,
                        role: roles.user,
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
    // check if user email exist in request payload
    // if email exist and if email is found in database then generate jwt token 
    // Set jwt token payload with user email, type of token and short expiration time
    // send a email to user with custom link for resetting password with token in link route path parameter 
    let foundUser = null;
    let { email } = req.body;

    if(!email) return res.status(300).send({
        message: "no email received",
    })
    
    foundUser = await User.findOne({email: email});

    if(!foundUser) return res.status(200).send({
        message: "If the account exist, a password reset email will be sent."
    });

    let resetToken =  sign({
        email: foundUser.email,
        id: foundUser.id,
        type: "passwordToken",
    }, process.env.SECRET_KEY, {expiresIn: "5m"});

    // configuration object for mailer sender object
    let transport = {
        host: process.env.TRANSPORT_HOST,
        port: process.env.TRANSPORT_PORT,
        auth: {
            user: process.env.TRANSPORT_AUTH_USER,
            pass: process.env.TRANSPORT_AUTH_PASS,
        }
    }

    let transporter = nodemailer.createTransport(transport);

    let message = {
        from: process.env.MESSAGE_FROM,
        to: foundUser.email,
        subject: "fifth test mail",
        text: `reset token = ${resetToken}`,
        html: `
        <h1>Password Reset Request</h1>
        <p>Please click the link below to reset your password:</p>
        <a href="http://${process.env.HOST}:${process.env.PORT}/auth/change-password?resetToken=${resetToken}">
            Reset Password
        </a>
        <p>If you did not request this, please ignore this email.</p>`,
    }
    
    transporter.sendMail(message, (err, info) => {
        if(err) {
            console.log(err);
            console.log(`error name = ${err.name}`);
            console.log(`error message = ${err.message}`);
            return res.status(500).json({...err});
        } 
        
        if(info) {
            console.log(`message send, ${info.id}`);
            return res.status(200).send("message sent");
        }
    });
});
app.post("/api/v1/auth/change-password", async (req, res, next) => {
    
});

// User Managament 

// Tweet Management
app.post("/api/v1/tweet/create", verifyAccessToken, verifyLogin, verifyRole, async (req, res, next) => {

    let tweetContent = req.body.content;
    let accessToken = req.get("authorization");
    let tokenPayload = null;
    let newTweet = null;

    try {
        if(accessToken.includes("Bearer")) {
            accessToken = accessToken.split(" ")[1];
        } else {
            accessToken = accessToken.trim();
        }
    
        tokenPayload = decode(accessToken);    
        console.log("jwt payload = ", tokenPayload);

        newTweet = new Tweet({
            content: tweetContent,
            author: tokenPayload.id,
            likeCount: 0,
        });

        await newTweet.save();

        res.status(200).send({newTweet});
    } catch(err) {
        console.log("error name = ", err.name);
        console.log("error message = ", err.message);
        res.status(500).send({
            name: err.name,
            message: err.message
        });
    }
});
app.get("/api/v1/tweet/search", async (req, res, next) => {
    // extract accessToken from request header
    // decode accessToken
    // extract search arguments from query parameter
    // build the search criteria
    // fetch tweet based on search criteria 

    let accessToken = req.get("authorization");
    let searchCriteria = {};
    let { content } = req.query;
    let decodedPayload = null;

    try {
        if(accessToken.includes("Bearer")) {
            accessToken = accessToken.split(" ")[1]; 
        } else {
            accessToken = accessToken.trim();
        }
        decodedPayload = decode(accessToken);

        if(content) {
            searchCriteria.content = content;
        }

        let result = await Tweet.findOne({
            content, 
            author: new mongoose.Types.ObjectId(decodedPayload.id)
        });

        if(!result) return res.status(200).send({
            name: "No result",
            message: "Tweet not found"
        })

        console.log("found tweet = ", result);

        res.status(200).send(result);
    } catch(err) {
        console.log("error name = ", err.name);
        console.log("error message = ", err.message);
        console.log(err);
        return res.status(500).send({
            name: err.name,
            message: err.message
        });
    }
})

app.patch("/api/v1/tweet/update/:id", verifyAccessToken, verifyLogin, verifyRole, async (req, res, next) => {
    // extract the accessToken from request header
    // decode the accessToken and store token payload
    // extract and store user id from token payload
    // extract and store tweet id from request params
    // extract and store updated tweet content from request body
    // find tweet using userId and tweetId
    // if found update its content with latest tweet
    // then return updated tweet in response
    // else return message no user found
    
    let accessToken = req.get("authorization");
    let { content } = req.body;
    let tweetId = req.params.id;
    let userId = null;
    let oldTweet = null;

    if(!accessToken) return res.status(400).send({
        name: "Invalid Request",
        message: "No authorization header"
    })

    if(!tweetId) return res.status(400).send({
        name: "Invalid Request",
        message: "Request params missing"
    });

    if(!content) return res.status(400).send({
        name: "Invalid Request",
        message: "Request body missing"
    });

    try {
        accessToken = accessToken.split(" ")[1].trim();
        userId = decode(accessToken);

        oldTweet = await Tweet.findOneAndUpdate(
            {_id: tweetId, author: new mongoose.Types.ObjectId(userId)}, 
            {content}
        );
        return res.status(200).send(oldTweet);

    } catch(err) {
        console.log("error name = ", err.name);
        console.log("error message = ", err.message);
        return res.status(500).send({
            name: err.name,
            message: err.message
        })
    }
});
app.delete("/api/v1/tweet/delete/:id", verifyAccessToken, verifyLogin, verifyRole, async(req, res, next) => {
    let tweetId = req.params.id;
    let accessToken = req.get("authorization");
    let tokenPayload = null;
    let userId = null;

    if(!tweetId) return res.status(400).send({name: "Invalid Request", message: "tweet id missing" });

    if(!accessToken) return res.status(400).send({name: "Forbidden", message: "Token is invalid"});

    if(accessToken.includes("Bearer")) {
        accessToken = accessToken.split(" ")[1].trim();
    }
    try {
        console.log("access Token = ", accessToken);
        tokenPayload = decode(accessToken);
        console.log("token payload = ", tokenPayload);

        userId = tokenPayload.id;
        
        let deletedDoc = await Tweet.findOneAndDelete({author: userId, _id: tweetId});
        console.log("deleted doc = ", deletedDoc);
        res.status(200).send(deletedDoc);

    } catch(err) {
        console.log("error name = ", err.name);
        console.log("error message = ", err.message);
        return res.status(500).send({
            name: err.name,
            message: err.message
        })
    }
});
// Follow Management
app.post("api/v1/follow/create-follow", verifyAccessToken,verifyLogin, verifyRole, (req, res, next) => {
    console.log("protected resource");
    res.send("protected resource");
});

// Search Managment

// Hastags Timeline

// Notification Management

// Admin Management

// Analytics Management

// Engagement Management
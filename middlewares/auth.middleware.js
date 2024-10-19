const { User } = require("../models/user.model");
const { sign, verify, decode } = require("jsonwebtoken");

function authenticateToken (req, res, next) {
    // extract token from request object header
    // if token dont exist then send Token missing in server response
    // else server starts with authentication
    // verify token signature if valid proceed
    // verify token expiration time
    // if token is valid 
    // then server start with token authorization
    // server extracts roles
    // if role has permission to access the route or resource then user id set in request object
    // then route path or resource is accessible for that user id and then pass request object to next middleware
    // else send status 403 unauthorized in server response

    let token = req.get("Authorization");
    let payload = null;
    let currentTimeInSeconds = 0;
    if(!token) return res.status(401).send("Token missing");

    try {
        token = token.split(" ")[1];
        
        // authentication
        // token signature validation
        payload = verify(token, process.env.SECRET_KEY);
        console.log(payload);

        // token expiration validation
        currentTimeInSeconds = Number((new Date().getTime()/1000).toFixed(0));
        
        // if payload found and current time is less than expiration time then token is valid 
        if(payload && (currentTimeInSeconds < payload.exp)) {
            console.log("token is valid");

            // authorization 
            // based on role
            if(payload.role === "user") {
                console.log("resource access granted");
                next();
            } else {
                return res.status(403).send({message: "unauthorized"});
            }
        }
        
    } catch(err) {
        console.log("error name = ", err.name);
        console.log("error message = ", err.message);
        return res.status(500).send({error: err});
    }
}

async function isLoggedOut(req, res, next) {
    // token version validation for logout check
    // extract payload from token
    // find user from database with the user id in the payload
    // if token version of founduser is same as payload token version then call next middleware
    // else return response to the client of 403 forbidden

    let token = req.get("Authorization").split(" ")[1];
    let foundUser = null;
    let decodedToken = decode(token);
    let { id, tokenVersion } = decodedToken;
    console.log("token payload = ", decodedToken);
    try {
        foundUser = await User.findOne({_id: id});
        console.log("foundUser = ", foundUser);

        if(foundUser.tokenVersion === tokenVersion) {
            next();
        } else{
            return res.status(403).send({message: "forbidden"});
        }
    } catch(err) {
        return res.status(500).send(err);
    }
}

module.exports = { authenticateToken, isLoggedOut };
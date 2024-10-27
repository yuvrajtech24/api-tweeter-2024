const { User } = require("../models/user.model");
const { verify, decode } = require("jsonwebtoken");

function verifyAccessToken (req, res, next) {
    // token validation
    // extract token from request object header
    // if token dont exist then send Token missing in server response
    // verify token signature and store result
    // verify token expiration time and store result
    // if signature and expiration result is valid call next middleware
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
            res.locals.payload = {...payload};
            next();
        }
    } catch(err) {
        console.log("error name = ", err.name);
        console.log("error message = ", err.message);
        return res.status(500).send({error: err});
    }
};
async function verifyLogin(req, res, next) {
    // token version validation for logout check
    // extract token from request header
    // decode token and extract payload
    // extract user from payload and find user in database
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

module.exports = { verifyAccessToken, verifyLogin };
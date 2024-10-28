// Imports
const { decode } = require("jsonwebtoken");
const { roles, rolePermissions } = require("../config/roles.config");

function verifyRole(req, res, next) {
    // authorization 
    // role based access control(RBAC)

    // extract token from request header
    // decode the token and extract payload
    // if the payload contains no role then return error
    // if permission of role matches route method or http method then call next middleware

    try {
        let accessToken = String(req.get("Authorization"));
        let payload = null;
        if(!accessToken) return res.status(400).send("token missing");

        if(accessToken.includes("Bearer")) {
            accessToken = accessToken.split(" ")[1];
        } else {
            accessToken = accessToken.trim();
        }

        payload = decode(accessToken);

        if(!(payload.role && typeof payload.role === "number")) {
            return res.status(500).send({
                type: "error",
                message: "Role not available",
            });
        }

        let rolesArray = Object.entries(roles);

        let userRoleArray = rolesArray.find(role => role.includes(payload.role));

        let userRoleName = userRoleArray[0];

        if(rolePermissions[userRoleName].includes(req.method)){
            console.log(rolePermissions[userRoleName]);
            next();
        } else {
            console.log("request method = ", req.method);
            console.log("role permissions = ", rolePermissions[userRoleName]);
            res.status(403).send({
                name: "error",
                message: "Forbidden"
            })
    }} catch(err) {
        console.log("error name = ", err.name);
        console.log("error message = ", err.message);
        return res.status(500).send({
            name: err.name,
            message: err.message
        });
    }
}

module.exports = { verifyRole }; 
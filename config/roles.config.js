const rolePermissions = {
    admin: ["POST", "GET", "PUT", "PATCH", "DELETE"],
    user: ["GET", "PUT", "PATCH", "POST", "DELETE"],
    guest: ["GET"],
}

const roles = {
    admin: 1099,
    user: 2345,
    guest: 6512
}

module.exports = {roles, rolePermissions};
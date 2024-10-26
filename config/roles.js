const roles = {
    admin: ["create", "read", "update", "delete"],
    user: ["read", "update"],
    guest: ["read"],
}

module.exports = {roles};
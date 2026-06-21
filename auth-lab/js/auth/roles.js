// ==========================
// ROLE DATABASE
// ==========================
const users = {

    admin: {
        password: "admin123",
        role: "admin"
    },

    analyst: {
        password: "analyst123",
        role: "analyst"
    },

    user: {
        password: "user123",
        role: "user"
    }
};

// ==========================
// GET USER ROLE
// ==========================
export function getUserRole(
    username
) {

    return users[username]?.role || null;
}

// ==========================
// VALIDATE USER
// ==========================
export function validateUserRole(
    username,
    password
) {

    const user =
        users[username];

    if (!user) {
        return null;
    }

    if (
        user.password !== password
    ) {
        return null;
    }

    return user.role;
}
const jwt = require('jsonwebtoken');

// In a real app, this should be in an environment variable
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-key-123';

const verifyToken = (token) => {
    if (!token) return null;
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch (err) {
        return null;
    }
};

module.exports = {
    verifyToken,
    JWT_SECRET
};

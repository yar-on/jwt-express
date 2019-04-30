module.exports = {
    UNKNOWN_ERROR: {
        httpCode: 500,
        message: 'Unknown error, please try again later.',
    },
    MISSING_TOKEN: {
        httpCode: 400,
        message: 'Missing token param.',
    },
    INVALID_TOKEN_SCHEMA: {
        httpCode: 400,
        message: 'Token schema is not allowed.',
    },
    INVALID_TOKEN: {
        httpCode: 401,
        message: 'Invalid token.',
    },
    CORRUPTED_TOKEN: {
        httpCode: 400,
        message: 'Corrupted token.',
    },
    TOKEN_BLACKLISTED: {
        httpCode: 401,
        message: 'Token in blacklist.',
    },
};
const errorCodes = require('./errorCodes');
module.exports = class JwtExpressError extends Error {
    static ErrorCodes = errorCodes;

    constructor(errorCode) {
        super();
        if (errorCodes[errorCode]) {
            this._errorCode = errorCode;
        } else {
            this._errorCode = errorCodes.UNKNOWN_ERROR;
        }
    }

    get errorCode() {
        return this._errorCode;
    }
};
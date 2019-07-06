const jwt = require('jsonwebtoken');
const crypter = require('../crypter');
const JwtExpressError = require('./errors');
const BlacklistManager = require('./blacklistManager');
const userParams = require('../userParams');

const responseError = (e, req, res, next) => {
    if (e instanceof Object) {
        // convert json web token error to local error object
        if (e.name === "TokenExpiredError") {
            e = new JwtExpressError(JwtExpressError.ErrorCodes.TOKEN_EXPIRED);
        } else if (e.name === "JsonWebTokenError" && typeof e.message === "string") {
            let parts = e.message.split('.');
            let extraObject = {};
            const errorCode = parts.shift().trim().toUpperCase().replace(new RegExp(' ', 'g'), '_');
            if (parts.length > 0) {
                parts = parts[0].split(':');
                if (parts.length === 2) {
                    extraObject[parts[0].trim().toLowerCase()] = parts[1].trim();
                }
            }
            if (errorCode) {
                e = new JwtExpressError(errorCode, extraObject);
            }
        }
    }
    if (e instanceof JwtExpressError) {
        const responses = userParams.get('localization.responses');
        const errorCode = e.errorCode;
        let response = responses.UNKNOWN_ERROR;
        if (responses[errorCode] instanceof Object) {
            response = responses[errorCode];
        }
        if (res.hasOwnProperty("status")) {
            res.status(response.httpCode);
            let message = response.message;
            if (message.includes('${')) {
                for (let key in e.extraObject) {
                    if (e.extraObject.hasOwnProperty(key) && ["string", "number"].includes(typeof e.extraObject.hasOwnProperty(key))) {
                        message.replace(new RegExp("{$" + key + "}", 'g'), e.extraObject[key]);
                    }
                }
            }
            if (req.header['Accept'] === 'application/json') {
                res.json({message: response.message});
            } else {
                res.send(response.message);
            }
        } else {
            next(new Error('Invalid response object'));
        }
    } else {
        next(e);
    }
};

module.exports = class JwtManager {
    /**
     * @callback jwtSignCallback
     * @param {Error|null} err
     * @param {string|null} token
     */
    /**
     * @param {*} payload
     * @param {Object} options
     * @param {jwtSignCallback} callback
     * @returns {null|string}
     */
    static sign(payload, options = {}, callback = null) {
        if (typeof callback !== "function") {
            callback = null;
        }
        if (!(options instanceof Object)) {
            options = {};
        }

        let token = null;
        let err = null;
        try {
            token = jwt.sign({payload: payload}, userParams.get('jwt.secret'), options);
            if (userParams.get('jwt.useEncrypt')) {
                token = crypter.encrypt(userParams.get('encryption.algorithm'), token, userParams.get('encryption.secret'));
            }
        } catch (e) {
            err = e;
        }
        if (callback) {
            callback(err, token);
        }
        return token;
    }

    /**
     * @callback jwtVerifyCallback
     * @param {Error|null} err
     * @param {*|null} token
     */
    /**
     * @param {string} token
     * @param {Object} options
     * @param {jwtVerifyCallback} callback
     * @param {boolean} onlyPayload
     * @returns {null|string}
     */
    static verify(token, options = {}, callback = null, onlyPayload = true) {
        if (typeof callback !== "function") {
            callback = null;
        }
        if (!(options instanceof Object)) {
            options = {};
        }

        onlyPayload = onlyPayload !== false;

        let payload = null;

        try {
            if (userParams.get('jwt.useEncrypt')) {
                token = crypter.decrypt(userParams.get('encryption.algorithm'), token, userParams.get('encryption.secret'))
            }
            payload = jwt.verify(token, userParams.get('jwt.secret'), options);
            if (onlyPayload) {
                payload = payload.payload;
            }
        } catch (e) {
            if (callback) {
                callback(e, null)
            } else {
                throw e;
            }
        }
        if (callback) {
            callback(null, payload);
        }
        return payload;
    }

    static middleware(req, res, next) {
        try {
            const token = userParams.get('jwt.getToken')(req);
            let err = null;
            if (!token) {
                throw new JwtExpressError(JwtExpressError.ErrorCodes.INVALID_TOKEN);
            } else {
                const tokenData = this.verify(token, userParams.get('jwt.options'), null, false);
                const tokenPayload = (tokenData instanceof Object) ? tokenData.payload : null;
                if (!tokenData || !tokenPayload) {
                    throw new JwtExpressError(JwtExpressError.ErrorCodes.CORRUPTED_TOKEN);
                } else {
                    if (userParams.get('jwt.useBlacklist')) {
                        const blacklistDriver = BlacklistManager.getDriver();
                        if (blacklistDriver.isExists(token)) {
                            throw new JwtExpressError(JwtExpressError.ErrorCodes.TOKEN_BLACKLISTED);
                        }
                    }
                    req[userParams.get('jwt.middleware.tokenPayloadKey')] = tokenPayload;
                    next();
                }
            }
        } catch (e) {
            responseError(e, req, res, next);
        }
    }

    static middlewareRefreshToken(req, res, next) {
        let tokenPayload = null;
        try {
            const token = userParams.get('jwt.getToken')(req);
            if (!token) {
                throw new JwtExpressError(JwtExpressError.ErrorCodes.INVALID_TOKEN);
            } else {
                const tokenData = this.verify(token, userParams.get('jwt.options'), null, false);
                tokenPayload = (tokenData instanceof Object) ? tokenData.payload : null;
                if (!tokenData || !tokenPayload) {
                    throw new JwtExpressError(JwtExpressError.ErrorCodes.CORRUPTED_TOKEN);
                } else {
                    if (userParams.get('jwt.useBlacklist')) {
                        const blacklistDriver = BlacklistManager.getDriver();
                        if (blacklistDriver.isExists(token)) {
                            throw new JwtExpressError(JwtExpressError.ErrorCodes.TOKEN_BLACKLISTED);
                        }
                    }
                }
            }
        } catch (e) {
            // validate is expired token
            if (e instanceof Object && e.name === 'TokenExpiredError') {
                const refreshToken = userParams.get('jwt.refresh.getToken')(req);
                if (!refreshToken) {
                    throw new JwtExpressError(JwtExpressError.ErrorCodes.INVALID_TOKEN);
                } else {
                    const refreshTokenData = this.verify(refreshToken, userParams.get('jwt.refresh.options'), null, false);
                    const refreshTokenPayload = (refreshTokenData instanceof Object) ? refreshTokenData.payload : null;
                    if (!refreshTokenData || !refreshTokenPayload) {
                        throw new JwtExpressError(JwtExpressError.ErrorCodes.CORRUPTED_TOKEN);
                    } else {
                        if (userParams.get('jwt.useBlacklist')) {
                            const blacklistDriver = BlacklistManager.getDriver();
                            if (blacklistDriver.isExists(refreshToken)) {
                                throw new JwtExpressError(JwtExpressError.ErrorCodes.TOKEN_BLACKLISTED);
                            }
                        }
                        if (JSON.stringify(tokenPayload) === JSON.stringify(refreshTokenPayload)) {
                            const newToken = this.sign(tokenPayload);
                            res.set('authorization', newToken);
                            next();
                        } else {
                            throw new JwtExpressError(JwtExpressError.ErrorCodes.CORRUPTED_TOKEN);
                        }
                    }
                }
            }
            responseError(e, req, res, next);
        }
    }

    static middlewareSignOut(req, res, next) {
        try {
            const token = userParams.get('jwt.getToken')(req);
            if (!token) {
                throw new JwtExpressError(JwtExpressError.ErrorCodes.INVALID_TOKEN);
            } else {
                const tokenData = this.verify(token, userParams.get('jwt.options'), null, false);
                const tokenPayload = (tokenData instanceof Object) ? tokenData.payload : null;
                if (!tokenData || !tokenPayload) {
                    throw new JwtExpressError(JwtExpressError.ErrorCodes.CORRUPTED_TOKEN);
                } else {
                    if (userParams.get('jwt.useBlacklist')) {
                        const blacklistDriver = BlacklistManager.getDriver();
                        if (blacklistDriver.isExists(token)) {
                            throw new JwtExpressError(JwtExpressError.ErrorCodes.TOKEN_BLACKLISTED);
                        } else {
                            blacklistDriver.set(token, tokenData.exp);
                        }
                    }
                    next();
                }
            }
        } catch (e) {
            responseError(e, req, res, next);
        }
    }
};
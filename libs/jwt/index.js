const jwt = require('jsonwebtoken');
const crypter = require('../crypter');
const JwtExpressError = require('./errors');
const BlacklistManager = require('./blacklistManager');
const userParams = require('../userParams');

module.exports = class JwtManager {
    static sign(payload, options = {}, callback = null) {
        if (typeof callback !== "function") {
            callback = null;
        }
        if (!(options instanceof Object)) {
            if (typeof options === "function") {
                callback = options;
            }
            options = {};
        }

        options = Object.assign({}, userParams.get('jwt.options'), options);
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
            callback(err, token)
        }
        return token;
    }

    static verify(token, callback = null, onlyPayload = true) {
        if (typeof callback !== "function") {
            callback = null;
        }
        onlyPayload = onlyPayload !== false;

        let payload = null;
        let err = null;
        try {
            if (userParams.get('jwt.useEncrypt')) {
                token = crypter.decrypt(userParams.get('encryption.algorithm'), token, userParams.get('encryption.secret'))
            }
            payload = jwt.verify(token, userParams.get('jwt.secret'));
            if (onlyPayload) {
                payload = payload.payload;
            }
        } catch (e) {
            err = e;
        }
        if (callback) {
            callback(err, payload)
        }
        return payload;
    }

    static decode(token, callback = null, onlyPayload = true) {
        if (typeof callback !== "function") {
            callback = null;
        }
        onlyPayload = onlyPayload !== false;

        let payload = null;
        let err = null;
        try {
            if (userParams.get('jwt.useEncrypt')) {
                token = crypter.decrypt(userParams.get('encryption.algorithm'), token, userParams.get('encryption.secret'))
            }
            payload = jwt.decode(token, userParams.get('jwt.secret'));
            if (onlyPayload) {
                payload = payload.payload;
            }
        } catch (e) {
            err = e;
        }
        if (callback) {
            callback(err, payload)
        }
        return payload;
    }

    static middleware(req, res, next) {
        try {
            const token = userParams.get(jwt.getToken)(req);
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
            if (e instanceof JwtExpressError) {
                const responses = userParams.get('localization.responses');
                const errorCode = e.errorCode;
                let response = responses.UNKNOWN_ERROR;
                if (responses[errorCode] instanceof Object) {
                    response = responses[errorCode];
                }
                res.status(response.httpCode);
                if (req.header['Accept'] === 'application/json') {
                    res.json({message: response.message});
                } else {
                    res.send(response.message);
                }
            } else {
                next(e);
            }
        }
    }

    static signRefresh(payload, options = {}, callback = null) {
        if (typeof callback !== "function") {
            callback = null;
        }
        if (!(options instanceof Object)) {
            if (typeof options === "function") {
                callback = options;
            }
            options = {};
        }
        options = Object.assign({}, userParams.get('jwt.refresj.options'), options);
        return this.sign(payload, options, callback);
    }

    static middlewareRefreshToken(req, res, next) {
        try {
            const token = userParams.get('jwt.getToken')(req);
            if (!token) {
                throw new JwtExpressError(JwtExpressError.ErrorCodes.INVALID_TOKEN);
            } else {
                const tokenData = this.decode(token, userParams.get('jwt.options'), null, false);
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
            }
        } catch (e) {
            if (e instanceof JwtExpressError) {
                const responses = userParams.get('localization.responses');
                const errorCode = e.errorCode;
                let response = responses.UNKNOWN_ERROR;
                if (responses[errorCode] instanceof Object) {
                    response = responses[errorCode];
                }
                res.status(response.httpCode);
                if (req.header['Accept'] === 'application/json') {
                    res.json({message: response.message});
                } else {
                    res.send(response.message);
                }
            } else {
                next(e);
            }
        }
    }
};
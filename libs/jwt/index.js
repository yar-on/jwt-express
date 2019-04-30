const jwt = require('jsonwebtoken');
const crypter = require('../crypter');
const JwtExpressError = require('./errors');
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

        options = Object.assign({}, userParams.get('jwt.options, options'));
        let token = null;
        let err = null;
        try {
            token = jwt.sign({payload: payload}, userParams.get('jwt.secret, options'));
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

    static verify(token, options = {}, callback = null) {
        if (typeof callback !== "function") {
            callback = null;
        }
        if (!(options instanceof Object)) {
            if (typeof options === "function") {
                callback = options;
            }
            options = {};
        }

        options = Object.assign({}, userParams.get('jwt, options'));
        let payload = null;
        let err = null;
        try {
            if (userParams.get('jwt.useEncrypt')) {
                token = crypter.decrypt(userParams.get('encryption.algorithm'), token, userParams.get('encryption.secret'))
            }
            payload = jwt.verify(token, userParams.get('jwt.secret, options')).payload;
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
                const tokenPayload = this.verify(token, userParams.get('jwt.options'));
                if (!tokenPayload) {
                    throw new JwtExpressError(JwtExpressError.ErrorCodes.CORRUPTED_TOKEN);
                } else {
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
};
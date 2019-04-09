const jwt = require('jsonwebtoken');
const usrParams = require('./params');
const crypter = require('./libs/crypter');
const JwtExpressError = require('./errors');

const DEFAULT_PROPS = {
    jwt: {
        options: {
            algorithm: 'HS256',
            expiresIn: '5m',
            // notBefore: undefined,
            // audience: undefined,
            // issuer: undefined,
            // jwtid: undefined,
            // subject: undefined,
            // noTimestamp: undefined,
            // header: undefined,
            // keyid: undefined,
            // mutatePayload: false
        },
        secret: null,
        useEncrypt: false,
        getToken: (req) => {
            if (req.headers && req.headers.authorization && typeof req.headers.authorization === "string") {
                const parts = req.headers.authorization.split(' ');
                if (parts.length === 2) {
                    const scheme = parts[0];
                    const token = parts[1];

                    if (scheme === "Bearer") {
                        return token;
                    } else {
                        throw new JwtExpressError(JwtExpressError.ErrorCodes.INVALID_TOKEN_SCHEMA);
                    }
                } else {
                    throw new JwtExpressError(JwtExpressError.ErrorCodes.INVALID_TOKEN);
                }
            } else {
                throw new JwtExpressError(JwtExpressError.ErrorCodes.MISSING_TOKEN);
            }
        },
        middleware: {
            tokenPayloadKey: 'user',
        },
    },
    encryption: {
        algorithm: 'aes-256-cbc',
    },
};

const initJwt = (propsJwt, forceReInit) => {
    const options = Object.assign({}, DEFAULT_PROPS.jwt.options, propsJwt.options);
    const secret = propsJwt.secret;
    if (!usrParams.jwt || forceReInit) {
        usrParams.jwt = {
            options: options,
            secret: secret,
        };
    }
};

const initEnctyption = (forceReInit) => {
    const encryption = Object.assign({}, DEFAULT_PROPS.encryption, usrParams.encryption);
    if (!usrParams.encryption || forceReInit) {
        usrParams.encryption = encryption;
    }
};

class JWTExpress {
    /**
     * Props Jwt options object properties
     * @typedef {Object} PropsJwtOptions
     * @property {String|null|undefined} algorithm
     * @property {String|Number|null|undefined} expiresIn
     * @property {String|null|undefined} notBefore
     * @property {String|null|undefined} audience
     * @property {String|Array<string>|null|undefined} issuer
     * @property {String|null|undefined} subject
     * @property {boolean|null|undefined} mutatePayload
     */

    /**
     * Props Jwt options object properties
     * @typedef {Object} PropsJwtMiddleware
     * @property {String|null|undefined} tokenPayloadKey
     */

    /**
     * Props Jwt  object properties
     * @typedef {Object} PropsJwt
     * @property {PropsJwtOptions|undefined} options
     * @property {PropsJwtMiddleware|undefined} middleware
     * @property {String} secret
     * @property {Boolean} useEncrypt
     * @property {Function} getToken
     */

    /**
     * Props Jwt  object properties
     * @typedef {Object} PropsEncrypt
     * @property {String|undefined} algorithm
     * @property {String} secret
     */

    /**
     * Props  object properties
     * @typedef {Object} Props
     * @property {PropsJwt} jwt
     * @property {PropsEncrypt} encryption
     */

    /**
     * Init params by user properties
     * @param {Props} props
     * @param {boolean} forceReInit
     */
    init(props, forceReInit = false) {
        forceReInit = (forceReInit === true);
        if (!usrParams.init || forceReInit) {
            usrParams.init = true;
            if (!(props instanceof Object)) {
                props = {};
            }
            initJwt(props.jwt, forceReInit);
            initEnctyption(forceReInit);
        }
    }

    sign(payload, options = {}, callback = null) {
        if (typeof callback !== "function") {
            callback = null;
        }
        if (!(options instanceof Object)) {
            if (typeof options === "function") {
                callback = options;
            }
            options = {};
        }

        options = Object.assign({}, usrParams.jwt.options, options);
        let token = null;
        let err = null;
        try {
            token = jwt.sign({payload: payload}, usrParams.jwt.secret, options);
            if (usrParams.jwt.useEncrypt) {
                token = crypter.encrypt(usrParams.encryption.algorithm, token, usrParams.encryption.secret)
            }
        } catch (e) {
            err = e;
        }
        if (callback) {
            callback(err, token)
        }
        return token;
    }

    verify(token, options = {}, callback = null) {
        if (typeof callback !== "function") {
            callback = null;
        }
        if (!(options instanceof Object)) {
            if (typeof options === "function") {
                callback = options;
            }
            options = {};
        }

        options = Object.assign({}, usrParams.jwt, options);
        let payload = null;
        let err = null;
        try {
            if (usrParams.jwt.useEncrypt) {
                token = crypter.decrypt(usrParams.encryption.algorithm, token, usrParams.encryption.secret)
            }
            payload = jwt.verify(token, usrParams.jwt.secret, options).payload;
        } catch (e) {
            err = e;
        }
        if (callback) {
            callback(err, payload)
        }
        return payload;
    }

    middleware(req, res, next) {
        try {
            const token = usrParams.jwt.getToken(req);
            if (!token) {
                throw new JwtExpressError(JwtExpressError.ErrorCodes.INVALID_TOKEN);
            } else {
                const tokenPayload = this.verify(token, usrParams.jwt.options);
                if (!tokenPayload) {
                    throw new JwtExpressError(JwtExpressError.ErrorCodes.CORRUPTED_TOKEN);
                } else {
                    req[usrParams.jwt.middleware.tokenPayloadKey] = tokenPayload;
                    next();
                }
            }
        } catch (e) {
            if (e instanceof JwtExpressError) {

            } else {
                next(e);
            }
        }
    }
}

module.exports = new JWTExpress();

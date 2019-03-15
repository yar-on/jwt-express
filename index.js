const jwt = require('jsonwebtoken');
const usrParams = require('./params');

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
    }
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
     * Props Jwt  object properties
     * @typedef {Object} PropsJwt
     * @property {PropsJwtOptions|undefined} options
     * @property {String} secret
     */

    /**
     * Props  object properties
     * @typedef {Object} Props
     * @property {PropsJwt} jwt
     */

    /**
     * Init params by user properties
     * @param {Props} props
     * @param {boolean} forceReInit
     */
    init(props, forceReInit = false) {
        forceReInit = (forceReInit === true);
        if (!usrParams || forceReInit) {
            if (props instanceof Object) {
                initJwt(props.jwt, forceReInit);
            }
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

    }
}

module.exports = new JWTExpress();

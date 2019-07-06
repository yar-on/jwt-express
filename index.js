const userParams = require('./libs/userParams');
const jwt = require('./libs/jwt');


module.exports = class JWTExpress {
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
     * Props Jwt middleware object properties
     * @typedef {Object} PropsJwtMiddleware
     * @property {String|null|undefined} tokenPayloadKey
     */

    /**
     * Props Jwt blacklist object
     * @typedef {Object} PropsJwtBlacklist
     * @property {String} driverName
     * @property {PropsJwtBlacklistDriverParams|null|undefined} driverParams
     */

    /**
     * Props Jwt blacklist driver params
     * @typedef {Object} PropsJwtBlacklistDriverParams
     * @property {String|Number|null|undefined} clearExpiredItemsInterval
     * @property {String|Number|null|undefined} clearExpiredItemsIntervalDelay
     */

    /**
     * Props Jwt  object properties
     * @typedef {Object} PropsJwt
     * @property {PropsJwtOptions|undefined} options
     * @property {PropsJwtMiddleware|undefined} middleware
     * @property {PropsJwtBlacklist|undefined} blacklist
     * @property {String} secret
     * @property {Boolean} useEncrypt
     * @property {Boolean} useBlacklist
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
     * Init Props by user params
     * @param {Props} params
     * @param {boolean} forceReInit
     */
    static init(params, forceReInit = false) {
        userParams.init(params)
    }

    /**
     * @param {*} payload
     * @param {Object} options
     * @param {jwtSignCallback} callback
     * @returns {null|string}
     */
    static sign(payload, options = {}, callback = null) {
        if (!(options instanceof Object)) {
            options = {};
        }

        options = Object.assign({}, userParams.get('jwt.options'), options);
        return jwt.sign(payload, options, callback);
    }

    /**
     * @param {string} token
     * @param {Object} options
     * @param {jwtVerifyCallback} callback
     * @param {boolean} onlyPayload
     * @returns {null|string}
     */
    static verify(token, options = {}, callback = null, onlyPayload = true) {
        if (!(options instanceof Object)) {
            options = {};
        }

        options = Object.assign({}, userParams.get('jwt.options'), options);
        return jwt.verify(token, options, callback, onlyPayload);
    }

    /**
     * @param {*} payload
     * @param {Object} options
     * @param {jwtSignCallback} callback
     * @returns {null|string}
     */
    static signRefresh(payload, options = {}, callback = null) {
        if (!(options instanceof Object)) {
            options = {};
        }

        options = Object.assign({}, userParams.get('jwt.refresh.options'), options);
        return jwt.sign(payload, options, callback);
    }

    /**
     * @param {string} token
     * @param {Object} options
     * @param {jwtVerifyCallback} callback
     * @param {boolean} onlyPayload
     * @returns {null|string}
     */
    static signVerify(token, options = {}, callback = null, onlyPayload = true) {
        if (!(options instanceof Object)) {
            options = {};
        }

        options = Object.assign({}, userParams.get('jwt.refresh.options'), options);
        return jwt.verify(token, options, callback, onlyPayload);
    }

    static middleware(req, res, next) {
        return jwt.middleware(req, res, next);
    }

    static middlewareRefreshToken(req, res, next) {
        return jwt.middlewareRefreshToken(req, res, next);
    }

    static middlewareSignOut(req, res, next) {
        return jwt.middlewareSignOut(req, res, next);
    }


};
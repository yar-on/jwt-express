const userParams = require('./libs/userParams');
const jwt = require('./libs/jwt');


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

    static middleware(req, res, next) {
        return jwt.middleware(req, res, next);
    }

    static sign(payload, options = {}, callback = null) {
        return jwt.sign(payload, options, callback);
    }

    static verify(token, options = {}, callback = null) {
        return jwt.verify(token, options, callback);
    }


}

module.exports = new JWTExpress();

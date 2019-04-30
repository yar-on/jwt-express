const Helpers = require('../helpers');
const JwtExpressError = require('../jwt/errors/index');

const DEFAULT_PARAMS = {
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
        blacklist: {
            driverName: 'memory',
            driverParams: {
                clearExpiredItemsInterval: '5m',
                clearExpiredItemsIntervalDelay: null,
            },
        },
    },
    encryption: {
        algorithm: 'aes-256-cbc',
    },
    localization: {
        responses: require('../localization/en/responses'),
    },
};
let firstInit = true;

module.exports = class UserParams {
    static init(params) {
        if (firstInit) {
            firstInit = false;
            this.userParams = Helpers.deepMerge(DEFAULT_PARAMS, params);
        }
    }

    static get(key) {
        if (key && typeof key === "string") {
            try {
                let keyArr = key.split('.');
                let val = this.userParams;
                let keyCount = keyArr.length;
                for (let i = 0; i < keyCount; i++) {
                    val = val[keyArr[i]];
                }
                return val;
            } catch (ignore) {
            }
        }
        return undefined;
    }

    static set(key, value) {
        if (key && typeof key === "string") {
            let keyArr = key.split('.');
            let val = this.userParams;
            let keyCount = keyArr.length;
            for (let i = 0; i < keyCount - 1; i++) {
                val = val[keyArr[i]];
                if (val === undefined || val === null) {
                    val = {};
                }
                if (!(val instanceof Object)) {
                    throw new Error(`${keyArr.slice(0, i + 1).join('.')} is not an object (actual type ${typeof val})`);
                }
            }
            val[keyArr[keyCount - 1]] = value;
        }
    }
};
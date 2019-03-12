const jwt = require('jsonwebtoken');


const DEFUALT_PROPS = {
    jwt: {
        options: {
            algorithm: 'HS256',
            expiresIn: '5m',
            notBefore: undefined,
            audience: undefined,
            issuer: undefined,
            jwtid: undefined,
            subject: undefined,
            noTimestamp: undefined,
            header: undefined,
            keyid: undefined,
            mutatePayload: false
        },
        secret: null,
    }
};

const props = {};

class JWTExpress {
    init(props) {

    }

    sign(payload, options = {}, callback = null) {

    }

    verify(token, options = {}, callback = null) {

    }

    middleware(req, res, next) {

    }
}

module.exports = new JWTExpress();

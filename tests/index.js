const {assert, expect} = require('chai');
const jwtExpress = require('../index');
const jwtObject = {name: 'blah'};

describe(`check jwt`, () => {
    it(`check basic jwt sign & verify`, () => {
        jwtExpress.init({
            jwt: {
                secret: 'P@ssw0rd',
            }
        }, true);
        const jwt = jwtExpress.sign(jwtObject);
        expect(jwt).to.be.a('string');
        expect(jwt).to.have.lengthOf.above(0);

        const jwtData = jwtExpress.verify(jwt);
        expect(jwtData).to.be.an('Object');
        expect(JSON.stringify(jwtData)).to.equal(JSON.stringify(jwtObject));

    });
});
# jwt-express

JsonWebToken (JWT) manager for express,

This module managing the authentication using [JSON Web Tokens](https://tools.ietf.org/html/rfc7519) for express application.
and allow you to encrypt the tokens and blacklist sign out tokens, 

this module also has middleware for authenticate and sign out


# Install

```bash
$ npm install jwt-express
```

# Initialize 

Before you can use this package in your app, you must initial it by this code: (the jwt.secret property is required for using this package)
```nodejs
var jwtExpress = require('jwt-express');

jwtExpress.init({
    jwt: {
        secret: 'asdasdasdasd',
    }
});

```

# usage

## Sign method
```nodejs
jwtExpress.sign(payload, [options = {}, callback = null])
```
Sign your payload with the initiated options for jwt.options.
`payload:` data you want to sign with jwt algorithm
`options:` override the initiated options to sign with.Must be type of object.
`callback:` should use callback function instead of return sync value of the sign method.
callback sign: function(Error|null,null|String)

## Verify method
```nodejs
jwtExpress.verify(token, [options = {}, callback = null, onlyPayload = true]) {
```
verify the token and return the payload value, using jwt.options as default options
`token:` token to be verified and get payload from
`options:` override the initiated options to sign with.Must be type of object.
`callback:` should use callback function instead of return sync value of the sign method.
callback sign: function(Error|null,null|String)
`onlyPayload:` indicate if return the payload data only or the whole token data

## Sign Refresh method
```nodejs
jwtExpress.signRefresh(payload, [options = {}, callback = null])
```
Sign your payload with the initiated options for jwt.refresh.options.
`payload:` data you want to sign with jwt algorithm
`options:` override the initiated options to sign with.Must be type of object.
`callback:` should use callback function instead of return sync value of the sign method.
callback sign: function(Error|null,null|String)


## Verify Refresh method
```nodejs
jwtExpress.verify(token, options = {}, callback = null, onlyPayload = true) {
```
verify the token and return the payload value, using jwt.refresh.options as default options
`token:` token to be verified and get payload from
`options:` override the initiated options to sign with.Must be type of object.
`callback:` should use callback function instead of return sync value of the sign method.
callback sign: function(Error|null,null|String)
`onlyPayload:` indicate if return the payload data only or the whole token data


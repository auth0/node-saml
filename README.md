# node-saml

Create SAML assertions. Supports SAML 1.1 and SAML 2.0 tokens.

[![Build Status](https://travis-ci.org/auth0/node-saml.png)](https://travis-ci.org/auth0/node-saml)

### Usage

#### Signed Assertions

```js
const saml = require('saml').Saml20; // or Saml11

const options = {
  cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
  key: fs.readFileSync(__dirname + '/test-auth0.key'),
  issuer: 'urn:issuer',
  lifetimeInSeconds: 600,
  audiences: 'urn:myapp',
  attributes: {
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': 'foo@bar.com',
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name': 'Foo Bar'
  },
  nameIdentifier: 'foo',
  sessionIndex: '_faed468a-15a0-4668-aed6-3d9c478cc8fa'
};

let samlAssertion = saml.create(options)

// OR with callbacks

saml.create(options, (err, samlAssertion) => {
  if (err) { throw new Error(err) }
  console.log(samlAssertion)
})
```

All options except of the cert and key are optional. The function can be invoked
either synchronously or with callbacks, however if the `encryptionCert` option
has been passed in, the syncronous invocation is not possible

#### Unsigned Assertions

```js
const saml = require('saml').Saml20; // or Saml11

const options = {
  issuer: 'urn:issuer',
  lifetimeInSeconds: 600,
  audiences: 'urn:myapp',
  attributes: {
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': 'foo@bar.com',
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name': 'Foo Bar'
  },
  nameIdentifier: 'foo',
  sessionIndex: '_faed468a-15a0-4668-aed6-3d9c478cc8fa'
};

let samlAssertion = saml.createUnsignedAssertion(options)

// OR with callbacks

saml.createUnsignedAssertion(options, (err, samlAssertion) => {
  if (err) { throw new Error(err) }
  console.log(samlAssertion)
})
```

All options are optional. The function can be invoked
either synchronously or with callbacks, however if the `encryptionCert` option
has been passed in, the syncronous invocation is not possible

## Issue Reporting

If you have found a bug or if you have a feature request, please report them at this repository issues section. Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.

## Author

[Auth0](auth0.com)

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.

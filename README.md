# node-saml

Create SAML assertions. Supports SAML 1.1 and SAML 2.0 tokens.

[![Build Status](https://travis-ci.org/auth0/node-saml.png)](https://travis-ci.org/auth0/node-saml)

### Supported Node Versions

node >= 12

### Usage

```js
var saml = require('saml').Saml20; // or Saml11

var options = {
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

var signedAssertion = saml.create(options);
```

Everything except the cert and key is optional.

## Issue Reporting

If you have found a bug or if you have a feature request, please report them at this repository issues section. Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.

## Author

[Auth0](auth0.com)

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.

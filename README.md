Create SAML assertions.

This is how we create SAML assertions for our SOAP requests. 

Major changes from this version of node-saml and the original:
- uses the ds: prefix
- uses holder-of-key confirmation method
- default encryption algorithms are changed around


### Usage

Everything except the cert and key is optional.

```js
var saml11 = require('saml').Saml11;

@@ -26,7 +28,24 @@ var options = {
var signedAssertion = saml11.create(options);
```

Everything except the cert and key is optional.
```js
var saml20 = require('saml').Saml20;

var samlOptions = {
  cert: fs.readFileSync(__dirname + '/test-auth0.pem'),
  key: fs.readFileSync(__dirname + '/test-auth0.key'),
  lifetimeInSeconds: 600,
  attributes: {
    'urn:oasis:names:tc:xspa:1.0:subject:subject-id': 'test',
    'urn:oasis:names:tc:xspa:1.0:subject:organization': 'testerino.'
  },
  nameIdentifier: 'foo',
  sessionIndex: '_faed468a-15a0-4668-aed6-3d9c478cc8fa'
};
saml20.create(samlOptions, callback);

```

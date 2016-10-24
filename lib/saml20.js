
var utils = require('./utils'),
    Parser = require('xmldom').DOMParser,
    SignedXml = require('xml-crypto').SignedXml,
    xmlenc = require('xml-encryption'),
    moment = require('moment');

var fs = require('fs');
var path = require('path');
var saml20 = fs.readFileSync(path.join(__dirname, 'saml20.template')).toString();

var NAMESPACE = 'urn:oasis:names:tc:SAML:2.0:assertion';

var algorithms = {
  signature: {
    'rsa-sha256': 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    'rsa-sha1':  'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
  },
  digest: {
    'sha256': 'http://www.w3.org/2001/04/xmlenc#sha256',
    'sha1': 'http://www.w3.org/2000/09/xmldsig#sha1'
  }
};

exports.create = function(options, callback) {
  if (!options.key)
    throw new Error('Expect a private key in pem format');

  if (!options.cert)
    throw new Error('Expect a public key cert in pem format');

  options.signatureAlgorithm = options.signatureAlgorithm || 'rsa-sha1';
  options.digestAlgorithm = options.digestAlgorithm || 'sha1';

  var cert = utils.pemToCert(options.cert);

  var sig = new SignedXml(null, { prefix: 'ds', signatureAlgorithm: algorithms.signature[options.signatureAlgorithm], idAttribute: 'ID' });
  sig.addReference("//*[local-name(.)='Assertion']",
                  ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"],
                  algorithms.digest[options.digestAlgorithm]);

  sig.signingKey = options.key;

  sig.keyInfoProvider = {
    getKeyInfo: function () {
      return "<ds:X509Data><ds:X509Certificate>" + cert + "</ds:X509Certificate></ds:X509Data>";
    }
  };

  var doc;
  try {
    doc = new Parser().parseFromString(saml20.toString());
  } catch(err){
    return utils.reportError(err, callback);
  }

  doc.documentElement.setAttribute('ID', '_' + (options.uid || utils.uid(32)));
  if (options.issuer) {
    var issuer = doc.documentElement.getElementsByTagName('saml2:Issuer');
    issuer[0].textContent = options.issuer;
  }

  var now = moment.utc();
  doc.documentElement.setAttribute('IssueInstant', now.format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));
  var conditions = doc.documentElement.getElementsByTagName('saml2:Conditions');
  var confirmationData = doc.documentElement.getElementsByTagName('saml2:SubjectConfirmationData');

  if (options.lifetimeInSeconds) {
    conditions[0].setAttribute('NotBefore', now.format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));
    conditions[0].setAttribute('NotOnOrAfter', now.clone().add('seconds', options.lifetimeInSeconds).format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));

    confirmationData[0].setAttribute('NotOnOrAfter', now.clone().add('seconds', options.lifetimeInSeconds).format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));
  }

  if (options.audiences) {
    var audiences = options.audiences instanceof Array ? options.audiences : [options.audiences];
    audiences.forEach(function (audience) {
      var element = doc.createElementNS(NAMESPACE, 'saml2:Audience');
      element.textContent = audience;
      var audienceCondition = conditions[0].getElementsByTagNameNS(NAMESPACE, 'AudienceRestriction')[0];
      audienceCondition.appendChild(element);
    });
  }

  if (options.recipient)
    confirmationData[0].setAttribute('Recipient', options.recipient);

  if (options.inResponseTo)
    confirmationData[0].setAttribute('InResponseTo', options.inResponseTo);

  if (options.attributes) {
    var statement = doc.documentElement.getElementsByTagNameNS(NAMESPACE, 'AttributeStatement')[0];
    Object.keys(options.attributes).forEach(function(prop) {
      if(typeof options.attributes[prop] === 'undefined') return;
      var attributeElement = doc.createElementNS(NAMESPACE, 'saml2:Attribute');
      attributeElement.setAttribute('Name', prop);
      var values = options.attributes[prop] instanceof Array ? options.attributes[prop] : [options.attributes[prop]];
      values.forEach(function (value) {
        var valueElement = doc.createElementNS(NAMESPACE, 'saml2:AttributeValue');
        valueElement.setAttribute('xsi:type', 'xs:anyType');
        valueElement.textContent = value;
        attributeElement.appendChild(valueElement);
      });

      if (values && values.length > 0) {
        // saml2:Attribute must have at least one saml2:AttributeValue
        statement.appendChild(attributeElement);
      }
    });
  }

  doc.getElementsByTagName('saml2:AuthnStatement')[0]
    .setAttribute('AuthnInstant', now.format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));

  if (options.sessionIndex) {
    doc.getElementsByTagName('saml2:AuthnStatement')[0]
      .setAttribute('SessionIndex', options.sessionIndex);
  }

  var nameID = doc.documentElement.getElementsByTagNameNS(NAMESPACE, 'NameID')[0];

  if (options.nameIdentifier) {
    nameID.textContent = options.nameIdentifier;
  }

  if (options.nameIdentifierFormat) {
    nameID.setAttribute('Format', options.nameIdentifierFormat);
  }

  if( options.authnContextClassRef ) {
    var authnCtxClassRef = doc.getElementsByTagName('saml2:AuthnContextClassRef')[0];
    authnCtxClassRef.textContent = options.authnContextClassRef;
  }

  var token = utils.removeWhitespace(doc.toString());
  var signed;
  try {
    sig.computeSignature(token, {
      prefix: 'ds'});
    signed = sig.getSignedXml();
  } catch(err){
    return utils.reportError(err, callback);
  }

  if (!options.encryptionCert) {
    if (callback)
      return callback(null, signed);
    else
      return signed;
  }


  var encryptOptions = {
    rsa_pub: options.encryptionPublicKey,
    pem: options.encryptionCert,
  };

  xmlenc.encrypt(signed, encryptOptions, function(err, encrypted) {
    if (err) return callback(err);
    encrypted = '<saml2:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">' + encrypted + '</saml2:EncryptedAssertion>';
    callback(null, utils.removeWhitespace(encrypted));
  });
};


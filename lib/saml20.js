
var utils = require('./utils'),
  Parser = require('xmldom').DOMParser,
  SignedXml = require('xml-crypto').SignedXml,
  xmlenc = require('xml-encryption'),
  moment = require('moment'),
  xmlNameValidator = require('xml-name-validator'),
  is_uri = require('valid-url').is_uri;

var fs = require('fs');
var path = require('path');
var saml20 = fs.readFileSync(path.join(__dirname, 'saml20.template')).toString();

var NAMESPACE = 'urn:oasis:names:tc:SAML:2.0:assertion';

var algorithms = {
  signature: {
    'rsa-sha256': 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    'rsa-sha1': 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
  },
  digest: {
    'sha256': 'http://www.w3.org/2001/04/xmlenc#sha256',
    'sha1': 'http://www.w3.org/2000/09/xmldsig#sha1'
  }
};

function getAttributeType(value) {
  switch (typeof value) {
    case "string":
      return 'xs:string';
    case "boolean":
      return 'xs:boolean';
    case "number":
      // Maybe we should fine-grain this type and check whether it is an integer, float, double xsi:types
      return 'xs:double';
    default:
      return 'xs:anyType';
  }
}

function getNameFormat(name) {
  if (is_uri(name)) {
    return 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri';
  }

  //  Check that the name is a valid xs:Name -> https://www.w3.org/TR/xmlschema-2/#Name
  //  xmlNameValidate.name takes a string and will return an object of the form { success, error },
  //  where success is a boolean
  //  if it is false, then error is a string containing some hint as to where the match went wrong.
  if (xmlNameValidator.name(name).success) {
    return 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic';
  }

  // Default value
  return 'urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified';
}

/**
* Gets the complere SAML Response merged with assertion (encrypted optional) and uses the
* saml20 argument options to set parts of the response utilizing the saml20Response.template file.
* @param assertion - the SAML assertion to add to the SAML response.
* @param options - The saml20 class options argument.
*/
function getSamlResponseXml(assertion, options) {
  var issueTime = new Date().toISOString();

  var assertionXml = new Parser().parseFromString(assertion);
  var saml20Response = fs.readFileSync(path.join(__dirname, 'saml20Response.template')).toString();

  var doc = new Parser().parseFromString(saml20Response.toString());

  doc.documentElement.setAttribute('ID', '_' + (options.uid || utils.uid(32)));
  doc.documentElement.setAttribute('IssueInstant', moment.utc().format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));
  doc.documentElement.setAttribute('Destination', options.destination);
  if (options.issuer) {
    var issuer = doc.documentElement.getElementsByTagName('saml:Issuer');
    issuer[0].textContent = options.issuer;
  }
  doc.lastChild.appendChild(assertionXml.documentElement);

  return doc.toString();
}

/**
* Signs the SAML XML at the Assertion level (default) or the Response Level (optional) using private key and cert.
* @param xmlToSign - The XML in string form containing the XML assertion or response.
* @param options - The saml20 class options argument.
*/
function signXml(xmlToSign, options) {
  // 0.10.1 added prefix, but we want to name it signatureNamespacePrefix - This is just to keep supporting prefix
  options.signatureNamespacePrefix = options.signatureNamespacePrefix || options.prefix;
  options.signatureNamespacePrefix = typeof options.signatureNamespacePrefix === 'string' ? options.signatureNamespacePrefix : '';

  var cert = utils.pemToCert(options.cert);
  var sig = new SignedXml(null, { signatureAlgorithm: algorithms.signature[options.signatureAlgorithm], idAttribute: 'ID' });
  var signingLocation = options.createSignedSamlResponse ? 'Response' : 'Assertion';
  sig.addReference("//*[local-name(.)='" + signingLocation + "']",
    ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"],
    algorithms.digest[options.digestAlgorithm]);

  sig.signingKey = options.key;

  var opts = {
    location: {
      reference: options.xpathToNodeBeforeSignature || "//*[local-name(.)='Issuer']",
      action: 'after'
    },
    prefix: options.signatureNamespacePrefix
  };

  sig.keyInfoProvider = {
    getKeyInfo: function (key, prefix) {
      prefix = prefix ? prefix + ':' : prefix;
      return "<" + prefix + "X509Data><" + prefix + "X509Certificate>" + cert + "</" + prefix + "X509Certificate></" + prefix + "X509Data>";
    }
  };

  sig.computeSignature(xmlToSign, opts);

  return sig.getSignedXml();
}

/**
* Encrypts s SAML assertion and formats with EncryptedAssertion wrapper using with provided cert.
* @param assertionToEncrypt - The SAML assertion to encrypt.
* @param options - The saml20 class options argument.
* @param callback - The callback function for ASYNC processing completion.
*/
function encryptAssertionXml(assertionToEncrypt, options, callback) {
  var encryptOptions = {
    rsa_pub: options.encryptionPublicKey,
    pem: options.encryptionCert,
    encryptionAlgorithm: options.encryptionAlgorithm || 'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
    keyEncryptionAlgorighm: options.keyEncryptionAlgorighm || 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p'
  };

  xmlenc.encrypt(assertionToEncrypt, encryptOptions, function (err, encrypted) {
    if (err) return callback(err);
    var assertion = '<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">' + encrypted + '</saml:EncryptedAssertion>';
    return callback(null, assertion);
  })
}

exports.create = function (options, callback) {
  if (!options.key)
    throw new Error('Expect a private key in pem format');

  if (!options.cert)
    throw new Error('Expect a public key cert in pem format');

  if (options.createSignedSamlResponse &&
       (!options.destination || options.destination.length < 1))
    throw new Error('Expect a SAML Response destination for message to be valid.')

  options.signatureAlgorithm = options.signatureAlgorithm || 'rsa-sha256';
  options.digestAlgorithm = options.digestAlgorithm || 'sha256';

  options.includeAttributeNameFormat = (typeof options.includeAttributeNameFormat !== 'undefined') ? options.includeAttributeNameFormat : true;
  options.typedAttributes = (typeof options.typedAttributes !== 'undefined') ? options.typedAttributes : true;

  var doc;
  try {
    doc = new Parser().parseFromString(saml20.toString());
  } catch (err) {
    return utils.reportError(err, callback);
  }

  doc.documentElement.setAttribute('ID', '_' + (options.uid || utils.uid(32)));
  if (options.issuer) {
    var issuer = doc.documentElement.getElementsByTagName('saml:Issuer');
    issuer[0].textContent = options.issuer;
  }

  var now = moment.utc();
  doc.documentElement.setAttribute('IssueInstant', now.format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));
  var conditions = doc.documentElement.getElementsByTagName('saml:Conditions');
  var confirmationData = doc.documentElement.getElementsByTagName('saml:SubjectConfirmationData');

  if (options.lifetimeInSeconds) {
    conditions[0].setAttribute('NotBefore', now.format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));
    conditions[0].setAttribute('NotOnOrAfter', now.clone().add(options.lifetimeInSeconds, 'seconds').format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));

    confirmationData[0].setAttribute('NotOnOrAfter', now.clone().add(options.lifetimeInSeconds, 'seconds').format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));
  }

  if (options.audiences) {
    var audienceRestriction = doc.createElementNS(NAMESPACE, 'saml:AudienceRestriction');
    var audiences = options.audiences instanceof Array ? options.audiences : [options.audiences];
    audiences.forEach(function (audience) {
      var element = doc.createElementNS(NAMESPACE, 'saml:Audience');
      element.textContent = audience;
      audienceRestriction.appendChild(element);
    });

    conditions[0].appendChild(audienceRestriction);
  }

  if (options.recipient)
    confirmationData[0].setAttribute('Recipient', options.recipient);

  if (options.inResponseTo)
    confirmationData[0].setAttribute('InResponseTo', options.inResponseTo);

  if (options.attributes) {
    var statement = doc.createElementNS(NAMESPACE, 'saml:AttributeStatement');
    statement.setAttribute('xmlns:xs', 'http://www.w3.org/2001/XMLSchema');
    statement.setAttribute('xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance');
    doc.documentElement.appendChild(statement);
    Object.keys(options.attributes).forEach(function (prop) {
      if (typeof options.attributes[prop] === 'undefined') return;
      // <saml:Attribute AttributeName="name" AttributeNamespace="http://schemas.xmlsoap.org/claims/identity">
      //    <saml:AttributeValue>Foo Bar</saml:AttributeValue>
      // </saml:Attribute>
      var attributeElement = doc.createElementNS(NAMESPACE, 'saml:Attribute');
      attributeElement.setAttribute('Name', prop);

      if (options.includeAttributeNameFormat) {
        attributeElement.setAttribute('NameFormat', getNameFormat(prop));
      }

      var values = options.attributes[prop] instanceof Array ? options.attributes[prop] : [options.attributes[prop]];
      values.forEach(function (value) {
        // Check by type, becase we want to include false values
        if (typeof value !== 'undefined') {
          // Ignore undefined values in Array
          var valueElement = doc.createElementNS(NAMESPACE, 'saml:AttributeValue');
          valueElement.setAttribute('xsi:type', options.typedAttributes ? getAttributeType(value) : 'xs:anyType');
          valueElement.textContent = value;
          attributeElement.appendChild(valueElement);
        }
      });

      if (values && values.filter(function (i) { return typeof i !== 'undefined'; }).length > 0) {
        // saml:Attribute must have at least one saml:AttributeValue
        statement.appendChild(attributeElement);
      }
    });
  }

  doc.getElementsByTagName('saml:AuthnStatement')[0]
    .setAttribute('AuthnInstant', now.format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));

  if (options.sessionIndex) {
    doc.getElementsByTagName('saml:AuthnStatement')[0]
      .setAttribute('SessionIndex', options.sessionIndex);
  }

  var nameID = doc.documentElement.getElementsByTagNameNS(NAMESPACE, 'NameID')[0];

  if (options.nameIdentifier) {
    nameID.textContent = options.nameIdentifier;
  }

  if (options.nameIdentifierFormat) {
    nameID.setAttribute('Format', options.nameIdentifierFormat);
  }

  if (options.authnContextClassRef) {
    var authnCtxClassRef = doc.getElementsByTagName('saml:AuthnContextClassRef')[0];
    authnCtxClassRef.textContent = options.authnContextClassRef;
  }

  var assertion = utils.removeWhitespace(doc.toString());

  // NEW: Option: build a complete signed SAML response with embedded (option encrypted) assertion
  if (options.createSignedSamlResponse) {
    try {
      // IF SAML response assertion is set to be encrypted
      if (options.encryptionCert) {
        encryptAssertionXml(assertion, options, function (err, encryptedAssertion) {
          if (err) return callback(err);
          var signedResponse = signSamlResponse(encryptedAssertion);
          return callback(null, signedResponse);
        });
      } else {
        // Do not encrypt assertion and send back
        var signedPlainResponse = signSamlResponse(assertion);
        return (callback) ? callback(null, signedPlainResponse) : signedPlainResponse;
      }
    } catch (err) {
      return (callback) ? callback(err) : err;
    }
  } else {
    try {
      // Sign the assertion always for both options
      var signedAssertion = signXml(utils.removeWhitespace(assertion), options);
      if (options.encryptionCert) {
        // If assertion is set to be encrypted
        encryptAssertionXml(signedAssertion, options, function (err, encryptedAssertion) {
          if (err) return callback(err);
          return callback(null, encryptedAssertion)
        });
      } else {
        // If assertion encryption not set just send back
        return (callback) ? callback(null, signedAssertion) : signedAssertion;
      }
    } catch (err) {
      return (callback) ? callback(err) : err;
    }
  }

  // Generates response with inserted assertion (or encrypted assertion) and signs
  function signSamlResponse(assertion) {
    var samlResponse = getSamlResponseXml(assertion, options);
    return signXml(utils.removeWhitespace(samlResponse), options);
  }

};

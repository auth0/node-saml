var utils = require('../utils');
var SignedXml = require('xml-crypto').SignedXml;

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

exports.fromSignXmlOptions = function (options) {
  if (!options.key)
    throw new Error('Expect a private key in pem format');

  if (!options.cert)
    throw new Error('Expect a public key cert in pem format');

  if (!options.xpathToNodeBeforeSignature)
    throw new Error('xpathToNodeBeforeSignature is required')

  var key = options.key;
  var pem = options.cert;
  var signatureAlgorithm = options.signatureAlgorithm || 'rsa-sha256';
  var digestAlgorithm = options.digestAlgorithm || 'sha256';
  var signatureNamespacePrefix = (function (prefix) {
    // 0.10.1 added prefix, but we want to name it signatureNamespacePrefix - This is just to keep supporting prefix
    return typeof prefix === 'string' ? prefix : '';
  })(options.signatureNamespacePrefix || options.prefix);
  var xpathToNodeBeforeSignature = options.xpathToNodeBeforeSignature;
  var idAttribute = options.signatureIdAttribute;

  /**
   * @param {Document} doc
   * @param {Function} [callback]
   * @return {string}
   */
  return function signXmlDocument(doc, callback) {
    var unsigned = exports.unsigned(doc);
    var cert = utils.pemToCert(pem);

    var sig = new SignedXml(null, { signatureAlgorithm: algorithms.signature[signatureAlgorithm], idAttribute: idAttribute });
    sig.addReference("//*[local-name(.)='Assertion']",
      ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"],
      algorithms.digest[digestAlgorithm]);

    sig.signingKey = key;

    sig.keyInfoProvider = {
      getKeyInfo: function (key, prefix) {
        prefix = prefix ? prefix + ':' : prefix;
        return "<" + prefix + "X509Data><" + prefix + "X509Certificate>" + cert + "</" + prefix + "X509Certificate></" + prefix + "X509Data>";
      }
    };

    sig.computeSignature(unsigned, {
      location: { reference: xpathToNodeBeforeSignature, action: 'after' },
      prefix: signatureNamespacePrefix
    });

    var signed = sig.getSignedXml();
    if (callback) {
      setImmediate(callback, null, signed);
    } else {
      return signed;
    }
  };
};

/**
 * @param {Document} doc
 * @param {Function} [callback]
 * @return {string}
 */
exports.unsigned = function (doc, callback) {
  var xml = utils.removeWhitespace(doc.toString());
  if (callback) {
    setImmediate(callback, null, xml)
  } else {
    return xml;
  }
}

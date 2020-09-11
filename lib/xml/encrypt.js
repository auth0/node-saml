var xmlenc = require('xml-encryption');

var utils = require('../utils');

exports.fromEncryptXmlOptions = function (options) {
  if (!options.encryptionCert) {
    return this.unencrypted;
  } else {
    return this.encrypted({
      rsa_pub: options.encryptionPublicKey,
      pem: options.encryptionCert,
      encryptionAlgorithm: options.encryptionAlgorithm || 'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
      keyEncryptionAlgorighm: options.keyEncryptionAlgorighm || 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p'
    });
  }
};

exports.unencrypted = function (xml, callback) {
  if (callback) {
    return setImmediate(callback, null, xml);
  } else {
    return xml;
  }
};

exports.encrypted = function (encryptOptions) {
  return function encrypt(xml, callback) {
    xmlenc.encrypt(xml, encryptOptions, function (err, encrypted) {
      if (err) return callback(err);
      callback(null, utils.removeWhitespace(encrypted));
    });
  };
};

const xmlenc = require('xml-encryption');

const utils = require('../utils');

exports.fromEncryptXmlOptions = function (options) {
  if (!options.encryptionCert) {
    return this.unencrypted;
  } else {
    const encryptOptions = {
      rsa_pub: options.encryptionPublicKey,
      pem: options.encryptionCert,
      encryptionAlgorithm: options.encryptionAlgorithm || 'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
      keyEncryptionAlgorithm: options.keyEncryptionAlgorithm || 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
    };

    // expose the encryptOptions as these are needed when adding the SubjectConfirmation
    return Object.assign(this.encrypted(encryptOptions), { encryptOptions: encryptOptions });
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
    try {
      xmlenc.encrypt(xml, encryptOptions, function (err, encrypted) {
        if (err) {
          throw err
        }
        callback(null, utils.removeWhitespace(encrypted));
      });
    } catch (err) {
      // Attempt to fix errors and retry
      console.warn(`Failed to encrypt xml. Attempting to fix errors and retrying. Error=${err.message}`)
      xmlenc.encrypt(xml,
      {
        ...encryptOptions,
        rsa_pub: utils.fixPemFormatting(encryptOptions.rsa_pub),
        pem: utils.fixPemFormatting(options.encryptionCert)
      },
      function (retryErr, retryEncrypted) {
        if (retryErr){
            callback(retryErr);
        } else {
            callback(null, utils.removeWhitespace(retryEncrypted));
        }
      });
    }
  };
};

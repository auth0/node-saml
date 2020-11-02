var path = require('path');
var utils = require('./utils');
var Parser = require('xmldom').DOMParser;
var xmlenc = require('xml-encryption');
var moment = require('moment');
var async = require('async');
var crypto = require('crypto');

var EncryptXml = require('./xml/encrypt');
var SignXml = require('./xml/sign');

var newSaml11Document = utils.factoryForNode(path.join(__dirname, 'saml11.template'));

var NAMESPACE = 'urn:oasis:names:tc:SAML:1.0:assertion';

function extractSaml11Options(opts) {
  return {
    uid: opts.uid,
    issuer: opts.issuer,
    lifetimeInSeconds: opts.lifetimeInSeconds,
    audiences: opts.audiences,
    attributes: opts.attributes,
    nameIdentifier: opts.nameIdentifier,
    nameIdentifierFormat: opts.nameIdentifierFormat,
    subjectConfirmationMethod: opts.subjectConfirmationMethod,
    holderOfKeyProofSecret: opts.holderOfKeyProofSecret
  };
}

/**
 * Creates a signed SAML 1.1 assertion from the given options.
 *
 * @param options
 *
 * // SAML
 * @param [options.uid] {string}
 * @param [options.issuer] {string}
 * @param [options.lifetimeInSeconds] {number}
 * @param [options.audiences] {string|string[]}
 * @param [options.attributes]
 * @param [options.nameIdentifier] {string}
 * @param [options.nameIdentifierFormat] {string}
 *
 * // XML Dsig
 * @param options.key {Buffer}
 * @param options.cert {Buffer}
 * @param [options.signatureAlgorithm] {string}
 * @param [options.digestAlgorithm] {string}
 * @param [options.signatureNamespacePrefix] {string}
 * @param [options.xpathToNodeBeforeSignature] {string}
 * @param [options.subjectConfirmationMethod] {string}
 * @param [options.holderOfKeyProofSecret] {Buffer}
 *
 * // XML encryption
 * @param [options.encryptionCert] {Buffer}
 * @param [options.encryptionPublicKey] {Buffer}
 * @param [options.encryptionAlgorithm] {string}
 * @param [options.keyEncryptionAlgorithm] {string}
 *
 * @param {Function} [callback] required if encrypting
 * @return {String|*}
 */
exports.create = function(options, callback) {
  return createAssertion(extractSaml11Options(options), {
    signXml: SignXml.fromSignXmlOptions(Object.assign({
      xpathToNodeBeforeSignature: "//*[local-name(.)='AuthenticationStatement']",
      signatureIdAttribute: 'AssertionID'
    }, options)),
    encryptXml: EncryptXml.fromEncryptXmlOptions(options)
  }, callback);
}

/**
 * Creates an **unsigned** SAML 1.1 assertion from the given options.
 *
 * @param options
 *
 * // SAML
 * @param [options.uid] {string}
 * @param [options.issuer] {string}
 * @param [options.lifetimeInSeconds] {number}
 * @param [options.audiences] {string|string[]}
 * @param [options.attributes]
 * @param [options.nameIdentifier] {string}
 * @param [options.nameIdentifierFormat] {string}
 *
 * // XML encryption
 * @param [options.encryptionCert] {Buffer}
 * @param [options.encryptionPublicKey] {Buffer}
 * @param [options.encryptionAlgorithm] {string}
 * @param [options.keyEncryptionAlgorithm] {string}
 *
 * @param {Function} [callback] required if encrypting
 * @return {String|*}
 */
exports.createUnsignedAssertion = function(options, callback) {
  return createAssertion(extractSaml11Options(options), {
    signXml: SignXml.unsigned,
    encryptXml: EncryptXml.fromEncryptXmlOptions(options)
  }, callback);
}

function createAssertion(options, strategies, callback) {
  var doc;
  try {
    doc = newSaml11Document();
  } catch(err){
    return utils.reportError(err, callback);
  }

  doc.documentElement.setAttribute('AssertionID', '_' + (options.uid || utils.uid(32)));
  if (options.issuer)
    doc.documentElement.setAttribute('Issuer', options.issuer);

  var now = moment.utc();
  doc.documentElement.setAttribute('IssueInstant', now.format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));
  var conditions = doc.documentElement.getElementsByTagName('saml:Conditions');

  if (options.lifetimeInSeconds) {
    conditions[0].setAttribute('NotBefore', now.format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));
    conditions[0].setAttribute('NotOnOrAfter', now.add(options.lifetimeInSeconds, 'seconds').format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));
  }
  
  if (options.audiences) {
    var audiences = options.audiences instanceof Array ? options.audiences : [options.audiences];
    audiences.forEach(function (audience) {
      var element = doc.createElementNS(NAMESPACE, 'saml:Audience');
      element.textContent = audience;
      var audienceCondition = conditions[0].getElementsByTagNameNS(NAMESPACE, 'AudienceRestrictionCondition')[0];
      audienceCondition.appendChild(element);
    });
  }

  if (options.attributes) {
    var statement = doc.documentElement.getElementsByTagNameNS(NAMESPACE, 'AttributeStatement')[0];
    Object.keys(options.attributes).forEach(function(prop) {
      if(typeof options.attributes[prop] === 'undefined') return;
      
      // <saml:Attribute AttributeName="name" AttributeNamespace="http://schemas.xmlsoap.org/claims/identity">
      //    <saml:AttributeValue>Foo Bar</saml:AttributeValue>
      // </saml:Attribute>
      var name = prop.indexOf('/') > -1 ? prop.substring(prop.lastIndexOf('/') + 1) : prop;
      var namespace = prop.indexOf('/') > -1 ? prop.substring(0, prop.lastIndexOf('/')) : '';
      var attributeElement = doc.createElementNS(NAMESPACE, 'saml:Attribute');
      attributeElement.setAttribute('AttributeNamespace', namespace);
      attributeElement.setAttribute('AttributeName', name);
      var values = options.attributes[prop] instanceof Array ? options.attributes[prop] : [options.attributes[prop]];
      values.forEach(function (value) {
        var valueElement = doc.createElementNS(NAMESPACE, 'saml:AttributeValue');
        valueElement.textContent = value;
        attributeElement.appendChild(valueElement);
      });

      if (values && values.length > 0) {
        // saml:Attribute must have at least one saml:AttributeValue
        statement.appendChild(attributeElement);
      }
    });
  }

  doc.getElementsByTagName('saml:AuthenticationStatement')[0]
    .setAttribute('AuthenticationInstant', now.format('YYYY-MM-DDTHH:mm:ss.SSS[Z]'));

  var nameID = doc.documentElement.getElementsByTagNameNS(NAMESPACE, 'NameIdentifier')[0];
  
  if (options.nameIdentifier) {
    nameID.textContent = options.nameIdentifier;
  
    doc.getElementsByTagName('saml:AuthenticationStatement')[0]
      .getElementsByTagName('saml:NameIdentifier')[0]
      .textContent = options.nameIdentifier;
  }
  
  if (options.nameIdentifierFormat) {
    var nameIDs = doc.documentElement.getElementsByTagNameNS(NAMESPACE, 'NameIdentifier');
    nameIDs[0].setAttribute('Format', options.nameIdentifierFormat);
    nameIDs[1].setAttribute('Format', options.nameIdentifierFormat);
  }

  if (strategies.encryptXml === EncryptXml.unencrypted) {
    var signed = strategies.signXml(doc);
    return strategies.encryptXml(signed, callback);
  }

  // encryption is turned on,
  var proofSecret;
  async.waterfall([
    function (cb) {
      if (!options.subjectConfirmationMethod && options.subjectConfirmationMethod !== 'holder-of-key')
        return cb();

      crypto.randomBytes(32, function(err, randomBytes) {
        proofSecret = randomBytes;
        addSubjectConfirmation(strategies.encryptXml.encryptOptions, doc, options.holderOfKeyProofSecret || randomBytes, cb);
      });
    },
    function(cb) {
      strategies.signXml(doc, cb);
    },
    function(signed, cb) {
      strategies.encryptXml(signed, cb);
    }
  ], function (err, result) {
    if (err) return callback(err);
    callback(null, result, proofSecret);
  });
}

function addSubjectConfirmation(encryptOptions, doc, randomBytes, callback) {
  xmlenc.encryptKeyInfo(randomBytes, encryptOptions, function(err, keyinfo) {
    if (err) return callback(err);
    var subjectConfirmationNodes = doc.documentElement.getElementsByTagNameNS(NAMESPACE, 'SubjectConfirmation');

    for (var i=0; i<subjectConfirmationNodes.length; i++) {
      var keyinfoDom;
      try {
        keyinfoDom = new Parser().parseFromString(keyinfo);
      } catch(error){
        return utils.reportError(error, callback);
      }

      var method = subjectConfirmationNodes[i].getElementsByTagNameNS(NAMESPACE, 'ConfirmationMethod')[0];
      method.textContent = 'urn:oasis:names:tc:SAML:1.0:cm:holder-of-key';
      subjectConfirmationNodes[i].appendChild(keyinfoDom.documentElement);
    }

    callback();
  });
}

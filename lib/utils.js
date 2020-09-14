var fs = require('fs');
var Parser = require('xmldom').DOMParser;

exports.pemToCert = function(pem) {
  var cert = /-----BEGIN CERTIFICATE-----([^-]*)-----END CERTIFICATE-----/g.exec(pem.toString());
  if (cert && cert.length > 0) {
    return cert[1].replace(/[\n|\r\n]/g, '');
  }

  return null;
};

exports.reportError = function(err, callback){
  if (callback){
    setImmediate(function(){
      callback(err);
    });
  }
};

/**
 * Return a unique identifier with the given `len`.
 *
 *     utils.uid(10);
 *     // => "FDaS435D2z"
 *
 * @param {Number} len
 * @return {String}
 * @api private
 */
exports.uid = function(len) {
  var buf = []
    , chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    , charlen = chars.length;

  for (var i = 0; i < len; ++i) {
    buf.push(chars[getRandomInt(0, charlen - 1)]);
  }

  return buf.join('');
};

exports.removeWhitespace = function(xml) {
  var trimmed = xml
                .replace(/\r\n/g, '')
                .replace(/\n/g,'')
                .replace(/>(\s*)</g, '><') //unindent
                .trim();
  return trimmed;
};

/**
 * Retrun a random int, used by `utils.uid()`
 *
 * @param {Number} min
 * @param {Number} max
 * @return {Number}
 * @api private
 */

function getRandomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

/**
 * Returns a function that can be called to create a new Node.
 *
 * @param {string} pathToTemplate an absolute path to a template file
 * @return {function(): Node}
 */
exports.factoryForNode = function factoryForNode(pathToTemplate) {
  var template = fs.readFileSync(pathToTemplate)
  var prototypeDoc = new Parser().parseFromString(template.toString())

  return function () {
    return prototypeDoc.cloneNode(true);
  };
};

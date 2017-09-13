var assert = require("assert"),
  utils = require("../lib/utils");

describe("saml 1.1", function() {
	describe("pemToCert", function() {
		it("should not throw when the cert is invalid", function() {
			var cert = utils.pemToCert('abc');
			assert.ok(!cert);
		});
	});
});

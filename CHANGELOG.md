# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

## [3.0.0](https://github.com/auth0/node-saml/compare/v2.0.1...v3.0.0) (2022-05-12)


### ⚠ BREAKING CHANGES

* handle poorly formatted PEM files (#85)

### Bug Fixes

* handle poorly formatted PEM files ([#85](https://github.com/auth0/node-saml/issues/85)) ([8830a23](https://github.com/auth0/node-saml/commit/8830a238d33e2e198acd81fb6d972583848bfe26))

### [2.0.1](https://github.com/auth0/node-saml/compare/v2.0.0...v2.0.1) (2022-02-09)


### Bug Fixes

* **saml11:** do not mutate moment() when options.lifetimeInSeconds is provided ([0a5afd1](https://github.com/auth0/node-saml/commit/0a5afd1977dc832f1cc51de6af7c801cc95f78b5))

## [2.0.0](https://github.com/auth0/node-saml/compare/v1.0.1...v2.0.0) (2022-02-04)


### ⚠ BREAKING CHANGES

* Requires NodeJS >= 12

Upgraded the xml-encryption package which removes the vulnerable node-forge dependency
See https://github.com/advisories/GHSA-8fr3-hfg3-gpgp

### Bug Fixes

* remove vulnerable node-forge dependency ([0106c61](https://github.com/auth0/node-saml/commit/0106c611a1263150e42692411aeeea0c95ec0755))

### [1.0.1](https://github.com/auth0/node-saml/compare/v1.0.0...v1.0.1) (2021-09-17)


### Bug Fixes

* update xmldom and xml-crypto to fix security issues ([6ad0243](https://github.com/auth0/node-saml/commit/6ad0243fe8c2f90d71d335500e9a9c8a2c436cb7))

## [1.0.0](https://github.com/auth0/node-saml/compare/v0.15.0...v1.0.0) (2020-11-04)


### ⚠ BREAKING CHANGES

* update xml-crypto and xmldom dependencies to fix sec issues
* stop supporting node v4 and v8
* xml-encryption major version bump, fix typo in config property
from `keyEncryptionAlgorighm` to `keyEncryptionAlgorithm` consumed by
new xml-encryption library version.

### Features

* fix sec issues with dependencies ([06acc02](https://github.com/auth0/node-saml/commit/06acc0238d7161c123f2f6924aa9f5984a5a2f32))
* update xml-crypto and xmldom dependencies to fix sec issues ([772c30e](https://github.com/auth0/node-saml/commit/772c30e4333d0af0e783c163e371c49ec0386c23))


* remove node v4 and v8 in travis configuration ([d8c62af](https://github.com/auth0/node-saml/commit/d8c62af972e6c6edbc052fafed749b254e73569c))

## [0.15.0](https://github.com/auth0/node-saml/compare/v0.13.0...v0.15.0) (2020-10-01)


### Features

* **saml11:** adds saml11.createUnsignedAssertion() ([51170c9](https://github.com/auth0/node-saml/commit/51170c91f5ddf9c31cb00b03fe5d8c513131e165))
* **saml20:** adds Saml20.createUnsignedAssertion() ([de0e766](https://github.com/auth0/node-saml/commit/de0e766f3fcb52913a93ff52cc1feefebf47eb00))
* **xml/sign:** unsigned assertions should have whitespace removed as well ([968d0e7](https://github.com/auth0/node-saml/commit/968d0e7559dd72f7d029752ced9887855e7d44c4))


### Bug Fixes

* **saml20:** parses saml20.template only once at start up ([cb3bfcd](https://github.com/auth0/node-saml/commit/cb3bfcdc4b034b6ac3ea52172c1be7d6193fddec))

'use strict';

var config = require('config');
var LE = require('letsencrypt');

// Storage Backend
var leStore = require('le-store-certbot').create({
  configDir: '~/letsencrypt/etc',                          // or /etc/letsencrypt or wherever
  debug: false
});

// ACME Challenge Handlers
var leChallenge = require('le-challenge-fs').create({
  webrootPath: '~/letsencrypt/var/',                       // or template string such as
  debug: false                                            // '/srv/www/:hostname/.well-known/acme-challenge'
});

var le = LE.create({
  server: LE.stagingServerUrl,                             // or LE.productionServerUrl
  store: leStore,                                          // handles saving of config, accounts, and certificates
  challenges: { 'http-01': leChallenge },                  // handles /.well-known/acme-challege keys and tokens
  challengeType: 'http-01',                                // default to this challenge type
  agreeToTerms: leAgree,                                   // hook to allow user to view and accept LE TOS
  //, sni: require('le-sni-auto').create({})               // handles sni callback
  //, debug: false
  ////, log: function (debug) {console.log.apply(console, args);} // handles debug outputs
});

var opts = {
  domains: ['example.com'], email: 'user@email.com', agreeTos: true
};

le.register(opts).then(function (certs) {
  console.log(certs);
  // privkey, cert, chain, expiresAt, issuedAt, subject, altnames
}, function (err) {
  console.error(err);
});

var app = express();
app.use('/', le.middleware());

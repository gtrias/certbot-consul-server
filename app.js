var _                = require('underscore');
var config           = require('config');
var LE               = require('letsencrypt');
var consulHost       = config.get('consul.host');
var express          = require('express');
var consul           = require('consul')({
    host: consulHost
});

// Storage Backend
var leStore = require('le-store-certbot').create({
  configDir: '~/letsencrypt/etc'                          // or /etc/letsencrypt or wherever
, debug: false
});


// ACME Challenge Handlers
var leChallenge = require('le-challenge-fs').create({
  webrootPath: '~/letsencrypt/var/'                       // or template string such as
, debug: false                                            // '/srv/www/:hostname/.well-known/acme-challenge'
});


function leAgree(opts, agreeCb) {
  // opts = { email, domains, tosUrl }
  agreeCb(null, opts.tosUrl);
}

le = LE.create({
  server: LE.stagingServerUrl,                             // or LE.productionServerUrl
  store: leStore,                                          // handles saving of config, accounts, and certificates
  challenges: { 'http-01': leChallenge },                  // handles /.well-known/acme-challege keys and tokens
  challengeType: 'http-01',                                // default to this challenge type
  agreeToTerms: leAgree,                                   // hook to allow user to view and accept LE TOS
//, sni: require('le-sni-auto').create({})                // handles sni callback
  debug: false,
//, log: function (debug) {console.log.apply(console, args);} // handles debug outputs
});

// Getting consul agent nodename to start watcher
consul.agent.self(function(err, result) {
    if (err) return console.log(err);
    var nodeName = result.Config.NodeName;
    startWatcher(nodeName);
});

// Starting watcher
function startWatcher(node) {
    console.log('Starting watcher');
    var watch = consul.watch({ method: consul.catalog.node.services, options: {'node': node}});

    watch.on('change', function(data, res) {
        requestCertificates(data);
    });

    watch.on('error', function(err) {
        console.log('error:', err);
    });
}


function requestCertificates(data) {
  console.log(data);
  var configurationPairs = extractDomainEmailPairs(data);
}

function extractDomainEmailPairs(data) {
  var groupedServices = _.groupBy(data, 'Service');

  var result;

  for (var i = 0; i < groupedServices.length; i++) {
    var pair;

    for (var j = 0; j < groupedServices[i].Tags.length; j++) {
      var kV = groupedServices[i].Tags[j].split('=');
      if (kV[0] && kV[0] === 'SSL_VIRTUAL_HOST'){
        pair['SSL_VIRTUAL_HOST'] = kV[1];
      }
      if (kV[0] && kV[0] === 'SSL_EMAIL'){
        pair['SSL_EMAIL'] = kV[1];
      }
    }
  }
}

var app = express();
app.use('/', le.middleware());

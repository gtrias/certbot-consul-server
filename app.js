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
  var configurationPairs = extractDomainEmailPairs(data);

  for (var i = 0; i < configurationPairs.length; i++) {
      var virtualHost = configurationPairs[i].SSL_VIRTUAL_HOST;
      var email = configurationPairs[i].SSL_EMAIL;
        // Check in-memory cache of certificates for the named domain
        le.check({ domains: [virtualHost] }).then(function (results) {
          if (results) {
            // we already have certificates
            return;
          }


          // Register Certificate manually
          le.register({
            domains:  [virtualHost],                         // CHANGE TO YOUR DOMAIN (list for SANS)
            email: email,
            agreeTos:  true,                                           // set to tosUrl string (or true) to pre-approve (and skip agreeToTerms)
            rsaKeySize: 2048,                                        // 2048 or higher
            challengeType: 'http-01'                                // http-01, tls-sni-01, or dns-01
          }).then(function (results) {
            console.log(results);

            console.log('success');

          }, function (err) {

            // Note: you must either use le.middleware() with express,
            // manually use le.challenges['http-01'].get(opts, domain, key, val, done)
            // or have a webserver running and responding
            // to /.well-known/acme-challenge at `webrootPath`
            console.error('[Error]: node-letsencrypt/examples/standalone');
            console.error(err.stack);

          });

        });

  }
}

/**
 * Convert services payload to key-value pairs with SSL_VIRTUAL_HOST and SSL_EMAIL
 */
function extractDomainEmailPairs(data) {
  var groupedServices = _.indexBy(data.Services, 'Service');

  // Hacky way to get object array
  var result = [];

  for (var property in groupedServices) {
      if (groupedServices.hasOwnProperty(property)) {
          var value = groupedServices[property];
          var pair = [];

          if (value.Tags) {

              for (var j = 0; j < value.Tags.length; j++) {
                  var kV = value.Tags[j].split('=');
                  if (kV[0] && kV[0] === 'SSL_VIRTUAL_HOST'){
                      pair['SSL_VIRTUAL_HOST'] = kV[1];
                  }
                  if (kV[0] && kV[0] === 'SSL_EMAIL'){
                      pair['SSL_EMAIL'] = kV[1];
                  }
              }

              if (pair['SSL_VIRTUAL_HOST'] && pair['SSL_EMAIL']) {
                  result.push(pair);
              }
          }

      }
  }

  return result;
}

var app = express();
app.use('/', le.middleware());


app.listen(54321, function () {
    console.log('Example app listening on port 3000!')
})

var _                = require('underscore');
var config           = require('config');
var LE               = require('greenlock');
var express          = require('express');
var consulHost       = config.get('consul.host');
var async            = require('async');
var concat           = require('concat-files');
var fs               = require('fs');
var consul           = require('consul')({
    host: consulHost
});

// Storage Backend
var leStore = require('le-store-certbot').create({
  configDir: config.get('letsencrypt.configDir'),  // or /etc/letsencrypt or wherever
  debug: false
});


// ACME Challenge Handlers
var leChallenge = require('le-challenge-fs').create({
  webrootPath: config.get('letsencrypt.webrootPath'),     // or template string such as
  debug: true                                            // '/srv/www/:hostname/.well-known/acme-challenge'
});


function leAgree(opts, agreeCb) {
  // opts = { email, domains, tosUrl }
  agreeCb(null, opts.tosUrl);
}

var server = LE.stagingServerUrl;

if (config.get('letsencrypt.server') === 'production') {
  server = LE.productionServerUrl;
}

le = LE.create({
  server: server,                                          // or LE.productionServerUrl
  store: leStore,                                          // handles saving of config, accounts, and certificates
  challenges: { 'http-01': leChallenge },                  // handles /.well-known/acme-challege keys and tokens
  challengeType: 'http-01',                                // default to this challenge type
  loopbackPort: config.get('letsencrypt.loopbackPort'),
  agreeToTerms: leAgree,                                   // hook to allow user to view and accept LE TOS
  debug: true,
  log: function (debug) {
    if (debug) {
      console.log('[Debug] %j', debug);
    }
  } // handles debug outputs
});

// Getting consul agent nodename to start watcher
function startListen() {
  consul.agent.self(function(err, result) {
    if (err) {
      startListen();
    } else {
      startWatcher(result);
    }
  });
}
// First execution
startListen();

// Starting watcher
function startWatcher(node) {
  var nodeName = node.Config.NodeName;
  var watch = consul.watch({ method: consul.catalog.service.list, options: {'node': nodeName}});

  watch.on('change', function(data, res) {
    var services = [];

    async.forEachOf(data, function(service, key, callback) {
      consul.catalog.service.nodes(key, function(err, result) {
        if (err) throw err;

        services.push({
          ID: key,
          nodes: result
        })

        callback();
      });
    }, function (err) {
      if (err) return console.log(err);

      requestCertificates(services);
    });

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
        // Ensure concatenation
        concatFiles(virtualHost, function (err) {
          if (err) {
            console.log('[Error] Failed to concate files');
          } else {
            console.log('[Success] files concated succesfully');
          }
        });

        // we already have certificates
        return;
      }

      // Register Certificate manually
      le.register({
        domains:  [virtualHost],   // CHANGE TO YOUR DOMAIN (list for SANS)
        email: email,
        agreeTos:  true,           // set to tosUrl string (or true) to pre-approve (and skip agreeToTerms)
        rsaKeySize: 2048,          // 2048 or higher
        challengeType: 'http-01'   // http-01, tls-sni-01, or dns-01
      }).then(function (results) {
        console.log('[Success]: %j', results);
        concatFiles(virtualHost, function (err) {
          if (err) {
            console.log('[Error] Failed to concate files');
          } else {
            console.log('[Success] files concated succesfully');
          }
        });


      }, function (err) {
        // Note: you must either use le.middleware() with express,
        // manually use le.challenges['http-01'].get(opts, domain, key, val, done)
        // or have a webserver running and responding
        // to /.well-known/acme-challenge at `webrootPath`

        console.error('[Error]: %j', err);
      });
    });
  }
}

function concatFiles(virtualHost, cb) {
  var certPath = '/certificates/etc/live/' + virtualHost + '/fullchain.pem';
  var privPath = '/certificates/etc/live/' + virtualHost + '/privkey.pem';
  if(fs.existsSync(certPath) && fs.existsSync(privPath) ) {
    var dest = '/certificates/etc/live/' + virtualHost + '/haproxy.pem';
    concat([
      certPath,
      privPath
    ], dest, function (err) {
      if (err) return cb(err);

      console.log("successfully created");

      return cb(null);
    });
  }
}

/**
 * Convert services payload to key-value pairs with SSL_VIRTUAL_HOST and SSL_EMAIL
 */
function extractDomainEmailPairs(data) {

  // Hacky way to get object array
  var result = [];

  data.forEach(function (element) {

  element.nodes.forEach(function (node) {

    var pair = [];
    if (node.ServiceTags) {

      for (var j = 0; j < node.ServiceTags.length; j++) {
          var kV = node.ServiceTags[j].split('=');
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

  });

});

  return result;
}

var app = express();
app.use('/', le.middleware());

var port = 54321;
app.listen(port, function () {
  console.log('Example app listening on port %s!', port)
})

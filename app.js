var config           = require('config');
var LE               = require('letsencrypt');
var consulHost       = config.get('consul.host');
var consul           = require('consul')({
    host: consulHost
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
}

var app = express();
app.use('/', le.middleware());

/*jslint node: true */
"use strict";

var conf = require('byteballcore/conf.js');
var eventBus = require('byteballcore/event_bus.js');
var db = require('byteballcore/db.js');
var util = require('util');
var fs = require('fs-extra');
var desktop = require('byteballcore/desktop_app.js');


function replaceConsoleLog() {
    var APP_DATA_DIR = desktop.getAppDataDir();
    fs.mkdirsSync(APP_DATA_DIR);
    var log_filename = APP_DATA_DIR + '/log.txt';
    var writeStream = fs.createWriteStream(log_filename);
    console.log('output to console is disabled (see ' + log_filename + ')');

    console.log = function () {
        writeStream.write(Date().toString() + ': ');
        writeStream.write(util.format.apply(null, arguments) + '\n');
    };
    console.warn = console.log;
    console.info = console.log;
}

function backConsoleLogging() {
    console.log = function (d) {
        process.stdout.write(util.format(d) + '\n');
    };
    console.warn = console.log;
    console.info = console.log;
}

eventBus.on('database_is_synced', function () {
    network.closeAllWsConnections();
    setTimeout(function () {
        backConsoleLogging();
        console.log('');
        db.query(
            "SELECT unit_authors.address, units.creation_date, messages.payload " +
            "FROM units JOIN messages USING(unit) " +
            "JOIN unit_authors USING(unit) " +
            "WHERE messages.app='data' ",
            function (rows) {
                rows.forEach(function (row) {
                    // var data = {
                    //     "content": "xxx",
                    //     "tags": [t1,t2,t3],
                    //     "creation_date" : {timestamp: new Date().getTime(), datetimeUTCString: new Date().toUTCString()}
                    // };
                    var payload = JSON.parse(row.payload);
                    console.log((payload.creation_date ? payload.creation_date.datetimeUTCString : "undefined") + ': ' + payload.tags + '\n'
                        + 'by: ' + row.address + '\n'
                        + JSON.stringify(payload.content) + '\n');
                });
                process.exit();
            });
    }, 100);
});

replaceConsoleLog();
var network = require('byteballcore/network.js');
network.findOutboundPeerOrConnect('ws://' + conf.hub);



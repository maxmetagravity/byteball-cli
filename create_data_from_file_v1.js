/*jslint node: true */
"use strict";

var args = process.argv.slice(2);
if (args && args.length < 2) {
    throw Error("2 arguments expected: 1-keysFile, 2-dataFile");
}

var eventBus = require('byteballcore/event_bus.js');
var db = require('byteballcore/db.js');
var util = require('util');
var constants = require('byteballcore/constants.js');
var conf = require('byteballcore/conf.js');
var objectHash = require('byteballcore/object_hash.js');
var ecdsaSig = require('byteballcore/signature.js');
var Mnemonic = require('bitcore-mnemonic');
var readline = require('readline');
var ecdsa = require('secp256k1');
var fs = require('fs-extra');
var desktop = require('byteballcore/desktop_app.js');

process.env.ENV_PASSPHRASE = "";

var signer = {
    readSigningPaths: function (conn, address, handleLengthsBySigningPaths) {
        handleLengthsBySigningPaths({r: constants.SIG_LENGTH});
    },
    readDefinition: function (conn, address, handleDefinition) {
        conn.query("SELECT definition FROM my_addresses WHERE address=?", [address], function (rows) {
            if (rows.length !== 1)
                throw "definition not found";
            handleDefinition(null, JSON.parse(rows[0].definition));
        });
    },
    sign: function (objUnsignedUnit, assocPrivatePayloads, address, signing_path, handleSignature) {
        var buf_to_sign = objectHash.getUnitHashToSign(objUnsignedUnit);
        var path = "m/44'/0'/0'/0/0";
        var privateKey = xPrivKey.derive(path).privateKey;
        var privKeyBuf = privateKey.bn.toBuffer({size: 32}); // https://github.com/bitpay/bitcore-lib/issues/47
        handleSignature(null, ecdsaSig.sign(buf_to_sign, privKeyBuf));
    }
};


function replaceConsoleLog() {
    var APP_DATA_DIR = desktop.getAppDataDir();
    fs.mkdirsSync(APP_DATA_DIR);
    var log_filename = APP_DATA_DIR + '/log.txt';
    var writeStream = fs.createWriteStream(log_filename);
    console.log('output to console is disabled (see ' + log_filename + ')');
    console.log('');

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

function readKeys(onDone) {
    fs.readFile(args[0], 'utf8', function (err, data) {
        var keys = JSON.parse(data);
        if (process.env.ENV_PASSPHRASE != null) {
            console.log("ENV_PASSPHRASE:'" + process.env.ENV_PASSPHRASE + "'");
            onDone(keys.mnemonic_phrase, process.env.ENV_PASSPHRASE);
        } else {
            var rl = readline.createInterface({
                input: process.stdin,
                output: process.stdout
            });
            rl.question("Enter passphrase: ", function (passphrase) {
                rl.close();
                if (process.stdout.moveCursor) process.stdout.moveCursor(0, -1);
                if (process.stdout.clearLine) process.stdout.clearLine();
                onDone(keys.mnemonic_phrase, passphrase);
            });
        }
    });
}

var xPrivKey;

eventBus.on('database_is_synced', function () {

        readKeys(function (mnemonic_phrase, passphrase) {
            var mnemonic = new Mnemonic(mnemonic_phrase);
            xPrivKey = mnemonic.toHDPrivateKey(passphrase);

            var privateKey = xPrivKey.derive("m/44'/0'/0'/0/0").privateKey;
            var privKeyBuf = privateKey.bn.toBuffer({size: 32}); // https://github.com/bitpay/bitcore-lib/issues/47
            var pubKey = ecdsa.publicKeyCreate(privKeyBuf, true).toString('base64');
            var address = objectHash.getChash160(["sig", {pubkey: pubKey}]);

            var composer = require('byteballcore/composer.js');

            function onError(err) {
                backConsoleLogging();
                throw Error(err);
            }

            var callbacks = composer.getSavingCallbacks({
                ifNotEnoughFunds: onError,
                ifError: onError,
                ifOk: function (objJoint) {
                    network.broadcastJoint(objJoint);
                    setTimeout(function () {
                        backConsoleLogging();
                        console.log('done');
                        process.exit();
                    }, 500);
                }
            });

            var data = require(args[1]);
            composer.composeDataJoint(address, data, signer, callbacks);
        });
    }
);

replaceConsoleLog();
var network = require('byteballcore/network.js');
network.findOutboundPeerOrConnect('ws://' + conf.hub);


'use strict';

const https = require('https');
const crypto = require('crypto');
const sigv4 = require('aws-signature-v4');

//aws overbridge host
const overbridgeHostname = 'overbridge.us-east-1.amazonaws.com';

//List Findings, GET
const overbridgeListPath = '/findings';

//Import findings, POST
const overbridgeImportPath = '/findings/import';

//decribe findings, POST
const overbridgeDescribePath = '/findings/describe';

const credentials = require('./aws-token.json').Credentials;

const sigv4_opts = {
    key: credentials.AccessKeyId,
    secret: credentials.SecretAccessKey,
    sessionToken: credentials.SessionToken,
    protocol: 'https',
    headers: {},
    region: 'us-east-1',
    query: 'X-Amz-Security-Token='+encodeURIComponent(credentials.SessionToken)
}

function createHash(plaintext, cb) {
    const test = crypto.createHash('sha256');
    test.on('readable', () => {
        const data = test.read();
        if( data ) {
            const hash = data.toString('hex');
            cb(hash);
        }
    });
    test.write(plaintext);
    test.end();
}

function overbridgeCall(method, path, post_data, cb) {
    const simpleHttpHandler = (res) => {
        const buffer = [];
        res.on('data', (data) => {
            buffer.push(data);
        });
        res.on('end', () => {
            try {
                const data = JSON.parse(buffer.join(''));
                if (cb) cb(data);
            } catch (e) {
                if (cb) cb(buffer.join(''));
            }
        });
    };
    sigv4_opts.timestamp = new Date();
    createHash(post_data, (hash) => {
        const sig = sigv4.createPresignedURL(method,
                                             overbridgeHostname,
                                             path,
                                             'overbridgebeta',
                                             hash,
                                             sigv4_opts);
        const options = {
            hostname: overbridgeHostname,
            path: path + '?' +sig.split('?')[1],
            method: method,
        };

        const req = https.request(options, simpleHttpHandler);

        req.write(post_data);
        req.end();
    });
}
module.exports.overbridgeCall = overbridgeCall;

function overbridgePromise(method, path, post_data) {
    return new Promise((resolve, reject) => {
        overbridgeCall(method, path, post_data, (data) => {
            //console.log(method, path, post_data);
            resolve(data);
        });
    });
};
module.exports.overbridgePromise = overbridgePromise;

function listFindings() {
    const account = '001474472906';
    const findingsQuery = {
        Filters: {
            AwsAccountId: [{
                Value: account,
                Comparison: 'EQUALS'
            }]
        }
    }
    return overbridgePromise('POST', overbridgeListPath, JSON.stringify(findingsQuery));
}
module.exports.listFindings = listFindings;

function importFindings(findings) {
    return overbridgePromise('POST',
                          overbridgeImportPath,
                          JSON.stringify(findings))
}
module.exports.importFindings = importFindings;

function describeFindings(findingIds) {
    const query = {
        "FindingIds": findingIds
    }
    return overbridgePromise('POST',
                          overbridgeDescribePath,
                          JSON.stringify(query));
}
module.exports.describeFindings = describeFindings;

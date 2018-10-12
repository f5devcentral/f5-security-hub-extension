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

/*
const credentials = {
    "SecretAccessKey": "LbJqXTWVvJB0NfBjnOtURgu/dWQMAhh7B31GEWhH",
    "SessionToken": "FQoGZXIvYXdzEM7//////////wEaDA/eVSod3YKGr2ycPCKsAYns7m1+GlB2+Dtt9aFUN4VuVYAzbekkDaMFeK6CDPfBZRVOk195W34yNE9evdWzzdTfHGCSJx5tqcZgjs/Z2NQKCTrDfm/WvHQ6UhDT9W6iIK6lfsPSbYlXu3OQHBDVEBibSujVnwOjtt45y2Le4qUNcwBsTW41KauVEgAD/0m49db/3B/8GrI6QDN7x/XTBvZRaBA5tDqoVmuVsrzSqHIIvVbUvrRlk8vQxsQoh+7+3QU=",
    "Expiration": "2018-10-12T08:48:07Z",
    "AccessKeyId": "ASIAQAV7CVPFBAHPNJMU"
}
*/

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
        //console.log('test readable!', plaintext);
        const data = test.read();
        if( data ) {
            const hash = data.toString('hex');
            //console.log('test hash:', hash);
            cb(hash);
        } else {
            //console.log('no data!');
        }
    });
    //console.log('writing...');
    test.write(plaintext);
    test.end();
    //console.log('digest', test.digest('hex'));
}

/*
  Resources: [
  {
  Type: 'AWS::EC2::Instance',
  Id: 'i-cafebabe',
  }
  ],

  Network: {
  SourceIpV4: event.ip_client,
  SourcePort: event.src_port,
  DestinationIpV4: event.dest_ip,
  DestinationPort: event.dest_port,
  Protocol: event.protocol
  }
*/

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

        //console.log(method, options);
        const req = https.request(options, simpleHttpHandler);

        req.write(post_data);
        req.end();
    });
}
module.exports.overbridgeCall = overbridgeCall;

function overbridgePromise(method, path, post_data) {
    return new Promise((resolve, reject) => {
        overbridgeCall(method, path, post_data, (data) => {
            resolve(data);
        });
    });
};
module.exports.overbridgePromise = overbridgePromise;



function listFindings() {
    return overbridgePromise('GET', overbridgeListPath, '');
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

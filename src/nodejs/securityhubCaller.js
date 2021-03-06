'use strict';

const https = require('https');
const crypto = require('crypto');
const sigv4 = require('aws-signature-v4');

//aws securityhub host
var securityhubHostname = 'securityhub.us-east-1.amazonaws.com';
var region = 'us-east-1';
const regionCfg = (r) => {
    securityhubHostname = `securityhub.${r}.amazonaws.com`;
    region = r;
}

//service string
const serviceString = 'securityhub'

//List Findings, GET
const securityhubListPath = '/findings';

//Import findings, POST
const securityhubImportPath = '/findings/import';

//decribe findings, POST
const securityhubDescribePath = '/findings/describe';

var sigv4_opts;
module.exports.sigv4_opts = sigv4_opts;
function setCredentials(credentials) {

    const token = credentials.SessionToken || credentials.Token;

    sigv4_opts =  {
        key: credentials.AccessKeyId,
        secret: credentials.SecretAccessKey,
        sessionToken: token,
        protocol: 'https',
        headers: {},
        region: region,
        query: 'X-Amz-Security-Token='+encodeURIComponent(token)
    };
}
module.exports.setCredentials = setCredentials;

const setRegion = (new_region) => {

    const supported = [ 'us-east-1',
                        'us-east-2',
                        'us-west-1',
                        'us-west-2',
                        'ap-south-1',
                        'ap-northeast-2',
                        'ap-southeast-1',
                        'ap-southeast-2',
                        'ap-northeast-1',
                        'ca-central-1',
                        'eu-central-1',
                        'eu-west-1',
                        'eu-west-2',
                        'eu-west-3',
                        'sa-east-1',
                      ];

    if( supported.some((e) => region === e )) {
        regionCfg(new_region);

        if(!sigv4_opts) {
            return new Error('Security credentials not set, is an appropriate IAM role attached, named BIGIPSecurityHubRole?');
        }
        
        sigv4_opts.region = new_region;
        return null;
    } else {
        return new Error('unsupported region: '+region);
    }
};
module.exports.setRegion = setRegion;

const getRegion = () => region;
module.exports.getRegion = getRegion;

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

function securityhubCall(method, path, post_data, cb) {
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
                                             securityhubHostname,
                                             path,
                                             serviceString,
                                             hash,
                                             sigv4_opts);
        const options = {
            hostname: securityhubHostname,
            path: path + '?' +sig.split('?')[1],
            method: method,
        };

        const req = https.request(options, simpleHttpHandler);

        req.on('error', (e) => {
            console.log(new Error('Error POSTing to SecurityHub:', e.message));
        });

        req.write(post_data);
        req.end();
    });
}
module.exports.securityhubCall = securityhubCall;

function securityhubPromise(method, path, post_data) {
    return new Promise((resolve, reject) => {
        securityhubCall(method, path, post_data, (data) => {
            //console.log(method, path, post_data);
            resolve(data);
        });
    });
};
module.exports.securityhubPromise = securityhubPromise;

function listFindings(query) {
    const findingsQuery = {
        Filters: query
    }
    //console.log(require('util').inspect(findingsQuery, {depth:null}));
    return securityhubPromise('POST', securityhubListPath, JSON.stringify(findingsQuery));
}
module.exports.listFindings = listFindings;

function importFindings(findings) {
    return securityhubPromise('POST',
                          securityhubImportPath,
                          JSON.stringify(findings))
}
module.exports.importFindings = importFindings;

function describeFindings(findingIds) {
    const query = {
        "FindingIds": findingIds
    }
    return securityhubPromise('POST',
                          securityhubDescribePath,
                          JSON.stringify(query));
}
module.exports.describeFindings = describeFindings;

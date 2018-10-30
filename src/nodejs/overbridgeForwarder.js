'use strict';

const net = require('net');
const util = require('util');
const http = require('http');
const EventEmitter = require('events').EventEmitter;

const aws = require('aws-sdk');

const f5_overbridge = require('./f5_overbridge.js');
const AsmLogStream = require('./asm_to_json.js').AsmLogStream;
const affFromEvent = require('./translate.js').affFromEvent;

function createLoggingProfile() {
    //use TMSH to create logging profile on the device
    // tmsh command for setting up logging
    const create_log_profile_command =
          [ 'create security log profile overbridge-logger application add { overbridge-logger-app { logger-type remote remote-storage remote format { field-delimiter , fields {',
            'attack_type',
            'blocking_exception_reason',
            'captcha_result',
            'client_type',
            'date_time',
            'dest_ip',
            'dest_port',
            'device_id',
            'geo_location',
            'http_class_name',
            'ip_address_intelligence',
            'ip_client',
            'ip_with_route_domain',
            'is_truncated',
            'login_result',
            'management_ip_address',
            'method',
            'mobile_application_name',
            'mobile_application_version',
            'policy_apply_date',
            'policy_name',
            'protocol',
            'query_string',
            'request',
            'request_status',
            'response',
            'response_code',
            'route_domain',
            'session_id',
            'severity',
            'sig_ids',
            'sig_names',
            'sig_set_names',
            'src_port',
            'staged_sig_ids',
            'staged_sig_names',
            'staged_sig_set_names',
            'sub_violations',
            'support_id',
            'unit_hostname',
            'uri',
            'username',
            'violation_details',
            'violation_rating',
            'violations',
            'virus_name',
            'websocket_direction',
            'websocket_message_type',
            'x_forwarded_for_header_value',
            ' } } servers add { 127.0.0.1:8514 } format { field-format none } } }'
          ].join(' ');

    const httpOpts = {
        host: 'localhost',
        port: '8100',
        path: '/mgmt/tm/util/bash',
        method: 'POST',
        auth: 'admin:f5p4ssw0rd!'
    };

    const postBody = {
        command: 'run',
        utilCmdArgs: `-c "tmsh ${create_log_profile_command}"`
    };

    const pReq = http.request(httpOpts, (res) => {
        this.logger.fine(res.statusCode);
        res.on('data', (data) => {
            this.logger.fine(data.toString('utf8'));
            console.log(data.toString('utf8'));
        });
    });
    pReq.write(JSON.stringify(postBody));
    pReq.end();

}

function refreshToken(self) {

    self.logger.fine('Renewing credentials');

    // Load the AWS SDK
    var AWS = require('aws-sdk'),
        region = "us-east-1",
        secretName = "f5/overbridge/aws_credentials",
        secret,
        decodedBinarySecret;

    // Create a Secrets Manager client
    var client = new AWS.SecretsManager({
        region: region
    });

    client.getSecretValue({SecretId: secretName}, function(err, data) {
        if (err) {
            self.logger.fine(err);
        } else {
            // Decrypts secret using the associated KMS CMK.
            // Depending on whether the secret is a string or binary, one of these fields will be populated.
            if ('SecretString' in data) {
                secret = data.SecretString;
            } else {
                let buff = new Buffer(data.SecretBinary, 'base64');
                decodedBinarySecret = buff.toString('ascii');
            }
            const raw = JSON.parse(data.SecretString);
            const credentials = {
                accessKeyId: raw.aws_access_key_id,
                secretAccessKey: raw.aws_secret_access_key
            }
            AWS.config = new AWS.Config(credentials);
            const stsClient = new AWS.STS({
                region: region
            });

            stsClient.getSessionToken({}, (err, data) => {
                if(err) self.logger.fine(err);
                else {
                    f5_overbridge.setCredentials(data.Credentials);
                    self.logger.fine('Token refreshed');
                }
            });
        }

    });
}

function startTokenRefresh(self) {
    refreshToken(self);
    return setInterval(() => {
        refreshToken(self);
    }, 43000000);
}


class OverbridgeForwarder extends EventEmitter {
    constructor(logger) {
        super();
        this.logger = logger;
        this.tokenRefreshInterval = startTokenRefresh(this);
        this.logForwarder = new net.createServer((socket) => {
            this.logger.fine(socket.remoteAddress + ' connected');
            new AsmLogStream(socket).on('data', (data) => {
                const event = JSON.parse(data);
                const finding = affFromEvent(event);
                const start = new Date();
                f5_overbridge.importFindings(finding).then((data) => {
                    //this.logger.fine('event',event);
                    this.logger.fine('Overbridge Post:', data);
                    if (data.FailedCount) {
                        this.logger.fine('Overbridge Failed finding:', util.inspect(finding, { depth: null }));
                    }
                });
            });

            socket.on('end', () => {
                this.logger.fine('Overbridge: BIG-IP disconnected ' + socket.remoteAddress);
            });

            socket.on('close', () => {
                this.logger.fine('Overbridge: BIG-IP disconnected ' + socket.remoteAddress);
            });
            socket.on('error', () => {
                this.logger.fine('Overbridge: BIG-IP isconnected ' + socket.remoteAddress);
            });
        });
    }
    
    listen(port, cb) {
        //start the overbridge remote log forwarder
        this.logForwarder.listen(port, (err) => {
            if (cb) cb();
        });
    }

}
module.exports = OverbridgeForwarder;

'use strict';

const fs = require('fs');
const net = require('net');
const util = require('util');
const http = require('http');
const EventEmitter = require('events').EventEmitter;

// Load the AWS SDK
var AWS = require('aws-sdk');

const securityhubCaller = require('./securityhubCaller.js');
const asm_to_json = require('./asm_to_json.js')
const AsmLogStream = asm_to_json.AsmLogStream,
      AsmObjectFilter = asm_to_json.AsmObjectFilter;
const translate = require('./translate.js');
const affFromEvent = translate.affFromEvent,
      setAccount = translate.setAccount;

const config = require('./configurationSchema.js');

// not currently used. left behind for possible future use. user must create logging profile themselves
function createLoggingProfile(cb) {
    //use TMSH to create logging profile on the device
    // tmsh command for setting up logging
    const create_log_profile_command =
          [ 'create security log profile securityhub-logger application add { securityhub-logger-app { logger-type remote remote-storage remote format { field-delimiter , fields {',
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
        auth: 'admin:'
    };

    const postBody = {
        command: 'run',
        utilCmdArgs: `-c "tmsh ${create_log_profile_command}"`
    };

    const pReq = http.request(httpOpts, (res) => {
        res.on('data', (data) => {
            if (cb) cb(data.toString('utf8'));
        });
    });
    pReq.write(JSON.stringify(postBody));
    pReq.end();

}
module.exports.createLoggingProfile = createLoggingProfile;

function refreshToken(self, fetchAccount) {

    self.logger.fine('[SecurityHub] Renewing AWS Token');

    const region = "us-east-1",
          secretName = "f5/securityhub/aws_credentials";
    var secret, decodedBinarySecret;

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
                var buff = new Buffer(data.SecretBinary, 'base64');
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

            if (fetchAccount) {
                stsClient.getCallerIdentity({}, (err, data) => {
                    if(err) self.logger.fine(err);
                    else {
                        self.logger.fine('[SecurityHub] Account Identified');
                        self.logger.fine('[SecurityHub] '+JSON.stringify(data));
                        setAccount(data);
                    }
                });
            }

            stsClient.getSessionToken({}, (err, data) => {
                if(err) self.logger.fine(err);
                else {
                    securityhubCaller.setCredentials(data.Credentials);
                    self.logger.fine('[SecurityHub] AWS Token refreshed');
                }
            });
        }

    });
}

function startTokenRefresh(self) {
    refreshToken(self, true);
    return setInterval(() => {
        refreshToken(self, false);
    }, 43000000);
}

const configPath = '/var/config/rest/iapps/f5-securityhub/configuration.json';

class SecurityHubForwarder extends EventEmitter {
    constructor(logger) {
        super();
        this.logger = logger;
        this.tokenRefreshInterval = startTokenRefresh(this);
        this.filter = new AsmObjectFilter();
        this.logForwarder = new net.createServer((socket) => {
            this.logger.fine('[SecurityHub]' + socket.remoteAddress + ' connected');
            new AsmLogStream(socket).on('data', (data) => {
                if( !this.filter.isFiltered(data) ) {
                    this.logger.fine('[SecurityHub] ASM Log entry not sent as finding: sig_names="'+data.sig_names+'"');
                    return;
                }

                const finding = affFromEvent(data);
                const start = new Date();
                securityhubCaller.importFindings(finding).then((data) => {
                    this.logger.fine('event',JSON.stringify(finding,2));
                    this.logger.fine('[SecurityHub] AFF Post:', data);
                    if (data.FailedCount) {
                        this.logger.fine('[SecurityHub] Failed finding:', util.inspect(finding, { depth: null }));
                    }
                });
            });

            socket.on('end', () => {
                this.logger.fine('[SecurityHub]: BIG-IP disconnected ' + socket.remoteAddress);
            });

            socket.on('close', () => {
                this.logger.fine('[SecurityHub]: BIG-IP disconnected ' + socket.remoteAddress);
            });
            socket.on('error', () => {
                this.logger.fine('[SecurityHub]: BIG-IP isconnected ' + socket.remoteAddress);
            });
        });

        fs.readFile(configPath, (err, data) => {
            if (err) {
                this.logger.fine(err);
            } else {
                this.postFilterRules(JSON.parse(data));
                this.logger.fine('[SecurityHub] Configuration loaded from '+configPath);
            }
        });
    }
    
    listen(port, cb) {
        //start the securityhub remote log forwarder
        this.logForwarder.listen(port, (err) => {
            if (cb) cb();
        });
    }

    getFilterRules() {
        return this.filter.filterRules;
    }

    postFilterRules(opts) {
        this.logger.fine('[SecurityHub] attempting to process configuration: ' + JSON.stringify(opts, null, 2));
        const valid = config.validate(opts);

        if( !valid ) {
            const result = config.errors();
            this.logger.fine('[SecurityHub] Invalid configuration: ' + JSON.stringify(result, null, 2));
            return {
                result: 'ERROR',
                message: result,
            }
        } else {
            fs.writeFile(configPath, JSON.stringify(opts, null, 2), (err) => {
                if (err) {
                    this.logger.fine('[SecurityHub] ERROR: Cannot write configuration to '+configPath);
                    this.logger.fine(err);
                } else {
                    this.logger.fine('[SecurityHub] Configuration updated at '+configPath);
                }
            });

            translate.setRegion(opts.Region);
            securityhubCaller.setRegion(opts.Region);

            const result = this.filter.setFilter(opts.Filter);
            this.logger.fine('[SecurityHub] Current ruleset: '+JSON.stringify(result));
            return {
                result: 'SUCCESS',
                message: opts,
            }
        }
    }

}
module.exports.SecurityHubForwarder = SecurityHubForwarder;

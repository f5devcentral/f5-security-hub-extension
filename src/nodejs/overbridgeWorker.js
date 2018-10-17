/*
  Copyright (c) 2017, F5 Networks, Inc.
  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at
  *
  http://www.apache.org/licenses/LICENSE-2.0
  *
  Unless required by applicable law or agreed to in writing,
  software distributed under the License is distributed on an
  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
  either express or implied. See the License for the specific
  language governing permissions and limitations under the License.
*/

'use strict';
const net = require('net');
const util = require('util');
const http = require('http');

const f5_overbridge = require('./f5_overbridge.js');
const AsmLogStream = require('./asm_to_json.js').AsmLogStream;
const affFromEvent = require('./translate.js').affFromEvent;

/**
 * @class OverbridgeWorker
 * @mixes RestWorker
 *
 * @description Starts the remote logging endpoint to forward ASM
 *   remote logging messages to AWS Overbridge
 */
function OverbridgeWorker() {
    this.state = {};
}

OverbridgeWorker.prototype.WORKER_URI_PATH = "shared/overbridge";

OverbridgeWorker.prototype.isPublic = true;

OverbridgeWorker.prototype.isPersisted = true;
OverbridgeWorker.prototype.isStateRequiredOnStart = false;

/******************
 * startup events *
 ******************/

/**
 * optional
 *
 * @description onStart will start the TCP listener and create a logging profile
 *   if one doesn't already exist
 *
 * @param {Function} success callback in case of success
 * @param {Function} error callback in case of error
 */
OverbridgeWorker.prototype.onStart = function(success, error) {

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
            ' } } servers add { 127.0.0.1:3000 } format { field-format none } } }'
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

    //start the overbridge remote log forwarder
    const logForwarder = new net.createServer((socket) => {
        this.logger.fine(socket.remoteAddress + ' connected');
        new AsmLogStream(socket).on('data', (data) => {
            const event = JSON.parse(data);
            const finding = affFromEvent(event);
            const start = new Date();
            f5_overbridge.importFindings(finding).then((data) => {
                //this.logger.fine('event',event);
                if (data.FailedCount || true) {
                    this.logger.fine(start, new Date());
                    this.logger.fine('finding', util.inspect(finding, { depth: null }));
                    this.logger.fine('response', data);
                }
            });
        });

        socket.on('end', () => {
           this.logger.fine('end disconnected ' + socket.remoteAddress);
        });

        socket.on('close', () => {
            this.logger.fine('close disconnected ' + socket.remoteAddress);
        });
        socket.on('error', () => {
            this.logger.fine('err disconnected ' + socket.remoteAddress);
        });
    });


    logForwarder.listen(3000);

    //if the logic in your onStart implementation encounters and error
    //then call the error callback function, otherwise call the success callback
    var err = false;
    if (err) {
        this.logger.severe("OverbridgeWorker onStart error: something went wrong");
        error();
    } else {
        this.logger.fine("OverbridgeWorker onStart success");
        success();
    }
};

/**
 * optional
 *
 * @description onStartCompleted is called after the dependencies are available
 * and state has been loaded from storage if worker is persisted with
 * isStateRequiredOnStart set to true. Framework will mark this worker available
 * to handle requests after success callback is called.
 *
 * @param {Function} success callback in case of success
 * @param {Function} error callback in case of error
 * @param {Object} state object loaded from storage
 * @param {Object|null} errMsg error from loading state from storage
 */
OverbridgeWorker.prototype.onStartCompleted = function (success, error, state, errMsg) {
    if (errMsg) {
        this.logger.severe("OverbridgeWorker onStartCompleted error: something went wrong " + errMsg);
        error();
    }

    this.logger.fine("OverbridgeWorker state loaded: " + JSON.stringify(state));
    success();
};

/*****************
 * http handlers *
 *****************/

/**
 * optional
 * handle onGet HTTP request
 * @param {Object} restOperation
 */
OverbridgeWorker.prototype.onGet = function(restOperation) {
    var oThis = this;

    if (!this.state.content) {
        restOperation.setBody(this.state);
        this.completeRestOperation(restOperation);
        return;
    }

    // Instead of returning what is in memory manually load the state
    // from storage using helper provided by restWorker and send that
    // in response
    this.loadState(null,

        function (err, state) {
            if (err) {
                oThis.logger.warning("[OverbridgeWorker] error loading state: %s", err.message);
                restOperation.fail(err);
                return;
            }
            restOperation.setBody(state);
            oThis.completeRestOperation(restOperation);
        }

    );
};

/**
 * optional
 * handle onPost HTTP request
 * @param {Object} restOperation
 */
OverbridgeWorker.prototype.onPost = function(restOperation) {
    this.state = restOperation.getBody();
    this.completeRestOperation(restOperation);
};

/**
 * optional
 * handle onPut HTTP request
 * @param {Object} restOperation
 */
OverbridgeWorker.prototype.onPut = function(restOperation) {
    this.state = restOperation.getBody();
    this.completeRestOperation(restOperation);
};


/**
 * optional
 * handle onPatch HTTP request
 * @param {Object} restOperation
 */
OverbridgeWorker.prototype.onPatch = function(restOperation) {
    this.state = restOperation.getBody();
    this.completeRestOperation(restOperation);
};


/**
 * optional
 * handle onDelete HTTP request
 * @param {Object} restOperation
 */
OverbridgeWorker.prototype.onDelete = function(restOperation) {
    this.state = {};
    this.completeRestOperation(restOperation.setBody(this.state));
};


module.exports = OverbridgeWorker;

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
const OverbridgeForwarder = require('./overbridgeForwarder.js');

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

OverbridgeWorker.prototype.storageUsesOdata = false;

//OverbridgeWorker.prototype.isPersisted = true;
//OverbridgeWorker.prototype.isStateRequiredOnStart = false;

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
    this.forwarder = new OverbridgeForwarder(this.logger);
    this.forwarder.listen(8514, (err) => {
        if (err) {
            this.logger.severe("[OverbridgeWorker] onStart error: something went wrong");
            error();
        } else {
            this.logger.fine("[OverbridgeWorker] onStart success");
            success();
        }
    });
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
    restOperation.setBody(this.forwarder.getFilterRules());
    this.completeRestOperation(restOperation);
};

/**
 * optional
 * handle onPost HTTP request
 * @param {Object} restOperation
 */
OverbridgeWorker.prototype.onPost = function(restOperation) {
    this.logger.fine(restOperation.getBody());
    this.forwarder.postFilterRules(JSON.parse(restOperation.getBody()));
    restOperation.setBody(this.forwarder.getFilterRules());
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

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
const shf = require('./securityhubForwarder.js');
const SecurityHubForwarder = shf.SecurityHubForwarder;
const createLoggingProfile = shf.createLoggingProfile;

/**
 * @class SecurityHubWorker
 * @mixes RestWorker
 *
 * @description Starts the remote logging endpoint to forward ASM
 *   remote logging messages to AWS SecurityHub
 */
function SecurityHubWorker() {
    this.state = {};
}

SecurityHubWorker.prototype.WORKER_URI_PATH = "shared/securityhub";

SecurityHubWorker.prototype.isPublic = true;

SecurityHubWorker.prototype.storageUsesOdata = false;

//SecurityHubWorker.prototype.isPersisted = true;
//SecurityHubWorker.prototype.isStateRequiredOnStart = false;

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
SecurityHubWorker.prototype.onStart = function(success, error) {
    createLoggingProfile((data) => {
        this.logger.fine(data);
    });
    this.forwarder = new SecurityHubForwarder(this.logger);
    this.forwarder.listen(8514, (err) => {
        if (err) {
            this.logger.severe("[SecurityHubWorker] onStart error: something went wrong");
            error();
        } else {
            this.logger.fine("[SecurityHubWorker] onStart success");
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
SecurityHubWorker.prototype.onGet = function(restOperation) {
    restOperation.setBody(this.state);
    this.completeRestOperation(restOperation);
};

/**
 * optional
 * handle onPost HTTP request
 * @param {Object} restOperation
 */
SecurityHubWorker.prototype.onPost = function(restOperation) {
    this.logger.fine(restOperation.getBody());
    const result = ((body) => {
        if( body instanceof Object )
            return this.forwarder.postFilterRules(body);

        try {
            return this.forwarder.postFilterRules(JSON.parse(body));
        } catch (e) {
            return {
                result: 'ERROR',
                message: 'Invalid JSON Body: ' + e.message,
            };
        }
    })(restOperation.getBody());

    if( result.result === 'ERROR' ){
        restOperation.setStatusCode(result.code || 422);
        restOperation.setBody({
            code: result.code || 422,
            message: result.message,
        });
    } else {
        this.state = restOperation.getBody();
        restOperation.setBody(result);
    }
    this.completeRestOperation(restOperation);
};

/**
 * optional
 * handle onPut HTTP request
 * @param {Object} restOperation
 */
SecurityHubWorker.prototype.onPut = function(restOperation) {
    restOperation.setStatusCode(405);
    restOperation.setBody({
        code: 405
    });
    this.completeRestOperation(restOperation);
};


/**
 * optional
 * handle onPatch HTTP request
 * @param {Object} restOperation
 */
SecurityHubWorker.prototype.onPatch = function(restOperation) {
    restOperation.setStatusCode(405);
    restOperation.setBody({
        code: 405
    });
    this.completeRestOperation(restOperation);
};


/**
 * optional
 * handle onDelete HTTP request
 * @param {Object} restOperation
 */
SecurityHubWorker.prototype.onDelete = function(restOperation) {
    restOperation.setStatusCode(405);
    restOperation.setBody({
        code: 405
    });
    this.completeRestOperation(restOperation.setBody(this.state));
};


module.exports = SecurityHubWorker;

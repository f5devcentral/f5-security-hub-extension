'use strict';

const net = require('net');
const util = require('util');

const f5_overbridge = require('./f5_overbridge.js');
const { listFindings, importFindings, describeFindings } = f5_overbridge;
const { AsmLogStream } = require('./asm_to_json.js');
const { affFromEvent } = require('./translate.js');

const logForwarder = new net.createServer((socket) => {
    console.log(socket.remoteAddress + ' connected');
    new AsmLogStream(socket).on('data', (data) => {
        const event = JSON.parse(data);
        const finding = affFromEvent(event);
        const start = new Date();
        importFindings(finding).then((data) => {
            //console.log('event',event);
            if (data.FailedCount || true) {
                console.log(start, new Date());
                console.log('finding', util.inspect(finding, { depth: null }));
                console.log('repsonse', data);
            }
        });
    });

    socket.on('end', () => {
        console.log('end disconnected ' + socket.remoteAddress);
    });

    socket.on('close', () => {
        console.log('close disconnected ' + socket.remoteAddress);
    });
    socket.on('error', () => {
        console.log('err disconnected ' + socket.remoteAddress);
    });
});


logForwarder.listen(3000);

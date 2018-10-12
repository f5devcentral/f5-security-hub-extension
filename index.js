'use strict';

const net = require('net');

const f5_overbridge = require('./f5_overbridge.js');
const { listFindings, importFindings, describeFindings } = f5_overbridge;
const { AsmLogStream } = require('./asm_to_json.js');
const { affFromEvent } = require('./translate.js');




const logForwarder = new net.createServer((socket) => {
    console.log(socket.remoteAddress + ' connected');
    new AsmLogStream(socket).on('data', (data) => {
        const event = JSON.parse(data);
        const finding = affFromEvent(event);
        console.log(event);
        console.log(finding);
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

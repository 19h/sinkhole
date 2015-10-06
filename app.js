'use strict';

let config = require('./config');

try {
    config = require('./config.local')
} catch (e) {
    console.log("Using default configuration! Copy config.js to config.local.js.");
}

var pcap = require('pcap'),
    pcap_session = pcap.createSession('', 'tcp'),
    matcher = /safari/i;

console.log('Listening on ' + pcap_session.device_name);

let beql = (b1, b2) => {
    if (b1.length !== b2.length) return false;

    for (let i = 0; i < b2.length; ++i)
        if (b1[i] !== b2[i]) return false;

    return true;
}

let lLbuf = config.host.split('.').map((i) => Number(i));

pcap_session.on('packet', (raw) => {
    let packet = pcap.decode.packet(raw);

    let data = packet.payload.payload;

    if (beql(data.daddr.addr, lLbuf))
        return false;

    let map = {
        source: {
            host: data.saddr.addr,
            port: data.payload.sport
        },
        dest: {
            host: data.daddr.addr,
            port: data.payload.dport
        }
    };

    console.log(map.source.host.join('.') + ':' + map.source.port + ' -> ' + map.dest.host.join('.') + ':' + map.dest.port);
});
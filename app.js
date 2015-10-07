'use strict';

let config = require('./config');

try {
    config = require('./config.local')
} catch (e) {
    console.log("Using default configuration! Copy config.js to config.local.js.");
}

let hyper = require('hyperlevel');
let db = hyper('./db');

var pcap = require('pcap'),
    pcap_session = pcap.createSession('', 'tcp'),
    matcher = /safari/i;

console.log('Using ' + pcap_session.device_name);

let beql = (b1, b2) => {
    if (b1.length !== b2.length) return false;

    for (let i = 0; i < b2.length; ++i)
        if (b1[i] !== b2[i]) return false;

    return true;
}

let a2i = (arr, bm) => {
    let ip = 0;

    if (!bm || bm >= 8)
        ip += arr[0] * (1 << 24);
    
    if (!bm || bm >= 16)
        ip += arr[1] * (1 << 16);
    
    if (!bm || bm >= 24)
        ip += arr[2] * (1 << 8);
    
    if (!bm || bm === 32)
        ip += arr[3];

    return ip;
};

var blacklist = {};

let blockSubnet = () => {

};

let blockHost = (ip) => {
    blacklist[ip] = true;
};

let lLbuf = config.host.split('.').map((i) => Number(i));

let hmap = {};

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

    let sub = map.dest.host.slice(0, 3).join('.');
    let id = map.dest.host[3];

    // initialize
    hmap[sub] = hmap[sub] || {};
    hmap[sub][id] = hmap[sub][id] || [];
    
    // add port & host
    if (!~hmap[sub][id].indexOf(map.dest.port)) {
        hmap[sub][id].push(map.dest.port);

        //console.log(sub, id, map.dest.port, hmap[sub][id].length);
    }

    // decide
    //if (hmap[sub].length > 4) {
        //console.log('Detected netscan: ', sub);
    //}

    // individual host
    if (hmap[sub][id].length > 10) {
        console.log('Detected portscan: ', sub + '.' + id, hmap[sub][id].join(', '));
    }

    clearTimeout(hmap[sub].timer);
    clearTimeout(hmap[sub][id].timer);

    hmap[sub][id].timer = setTimeout(() => {
        console.log('Removing ' + sub + '.' + id + ' due to inactivity.');

        clearTimeout(hmap[sub][id].timer);

        delete hmap[sub][id];
    }, config.eTTL);

    hmap[sub].timer = setTimeout(() => {
        console.log('Removing ' + sub + ' due to inactivity.');

        delete hmap[sub];
    }, config.eTTL);
});

//setInterval(() => console.log(hmap), 2000);
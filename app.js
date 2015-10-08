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

var hostBlacklist = {},
    subnetBlacklist = {};

let blockSubnet = (subnet) => {
    subnetBlacklist[subnet] = true;

    console.log("Executing: iptables -A OUTPUT -p all -m iprange --src-range " + subnet + ".0-" + subnet + ".255.255 -j DROP");

    setTimeout(() => {
        delete subnetBlacklist[subnet];
    }, 24 * 3600);
};

let blockHost = (ip) => {
    hostBlacklist[ip] = true;

    console.log("Executing: iptables -I OUTPUT -s " + ip + " -j DROP");

    setTimeout(() => {
        delete hostBlacklist[ip];
    }, 24 * 3600);
};

let lLbuf = config.host.split('.').map((i) => Number(i));

let hmap = {}; let metahmap = {};

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
    metahmap[sub] = metahmap[sub] || { length: 0 };

    if (!hmap[sub][id]) {
        metahmap[sub].length++;
    }

    hmap[sub][id] = hmap[sub][id] || [];

    // add port & host
    if (!~hmap[sub][id].indexOf(map.dest.port)) {
        hmap[sub][id].push(map.dest.port);

        //console.log(sub, id, map.dest.port, hmap[sub][id].length);
    }

    // decide
    if (metahmap[sub].length > 20) {
        if (subnetBlacklist[sub]) return;

        let ips = Object.keys(hmap[sub]);
            ips = ips.filter((i) => !isNaN(i)).join(',');
            ips = ips.map((i) => '[' + hmap[sub][id].join(', ') + ']')

        console.log('Detected netscan: ', sub, ips.join(', '));

        blockSubnet(sub);
    }

    // individual host
    if (hmap[sub][id].length > 20) {
        if (hostBlacklist[sub + '.' + id]) return;

        console.log('Detected portscan: ', sub + '.' + id, hmap[sub][id].join(', '));

        blockHost(sub + '.' + id);
    }

    clearTimeout(hmap[sub].timer);
    clearTimeout(hmap[sub][id].timer);

    hmap[sub][id].timer = setTimeout(() => {
        clearTimeout(hmap[sub][id].timer);

        delete hmap[sub][id];

        metahmap[sub].length--;
    }, config.eTTL);

    hmap[sub].timer = setTimeout(() => {
        delete hmap[sub];
        delete metahmap[sub];
    }, config.eTTL);
});

//setInterval(() => console.log(hmap), 2000);

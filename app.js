'use strict';

let childProcess = require('child_process');

let config = require('./config');

try {
    config = require('./config.local')
} catch (e) {
    console.log("Using default configuration! Copy config.js to config.local.js.");
}

let pcap = require('pcap');

let level = null;

try {
    level = require('hyperlevel');
} catch(e) {
    level = require('level');
}

let bloom = require('bloem').Bloem;

/* datastores */
// blacklist persistence
let db = level('./db', {
    valueEncoding: 'json'
});

let subnetPrefix = '\xFFsubnet\xFF',
    hostPrefix = '\xFFhost\xFF';

// bloomfilter for whitelist
let wl = new bloom(1024 * 128, 2);

let sentinel = (tgt) => {
    //return childProcess.spawn('tcpkill', ['-9', tgt])
    console.log('tcpkill', ['-9', tgt]);
};

let init = () => {
    let pcap_session = pcap.createSession('', 'tcp');

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

    let hostBlacklist = {},
        subnetBlacklist = {};

    let blockSubnet = (subnet) => {
        subnetBlacklist[subnet] = true;

        console.log("Executing: iptables -A OUTPUT -p all -m iprange --src-range " + subnet + ".0-" + subnet + ".255.255 -j DROP");

        db.put(subnetPrefix + subnet, {
            ts: Date.now(),
            sn: subnet
        }, () => {
            setTimeout(() => {
                db.del(subnetPrefix + subnet, () => {
                    delete subnetBlacklist[subnet];
                });
            }, 24 * 3600);
        });
    };

    let blockHost = (ip) => {
        hostBlacklist[ip] = true;

        console.log("Executing: iptables -I OUTPUT -s " + ip + " -j DROP");

        db.put(hostPrefix + ip, {
            ts: Date.now(),
            ip: ip
        }, () => {
            setTimeout(() => {
                db.del(hostPrefix + ip, () => {
                    delete hostBlacklist[ip];
                });
            }, 24 * 3600);
        });
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
        let ip = map.dest.host.join('.');

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
                ips = ips.filter((i) => !isNaN(i));
                ips = ips.map((i) => '[' + hmap[sub][id].join(', ') + ']')

            console.log('Detected netscan: ', sub, ips.join(', '));

            blockSubnet(sub);
        }

        // individual host
        if (hmap[sub][id].length > 20) {
            if (hostBlacklist[ip]) return;

            let ignored = wl.has(ip);

            console.log('Detected portscan' + (ignored ? ', ignoring' : '') + ': ', ip, hmap[sub][id].join(', '));

            blockHost(ip);
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
};

let ingestTorConsensus = () => {
    /* Aggregate IPs */
    let http = require('http');

    http.request('http://r3.geoca.st:9030/tor/status-vote/current/consensus', (sock) => {
        let data = Buffer(0);

        sock.on('data', (chunk) => {
            console.log(chunk)

            data = Buffer.concat([data, chunk]);
        });

        sock.on('end', () => {
            data = data
            // convert buffer to string
            .toString()
            // split into lines
            .split("\n")
            // select lines starting with 'r '
            .filter((i) => i[0] === 'r' && i[1] === ' ')
            // extract IP in line
            .map((i) => i.split(' ')[6])
            // feed into bloom filter
            .forEach((i) => wl.add(i));

            init();
        })
    }).end();
};

db.createReadStream()
.on('data', (item) => {
    console.log(item);

    let sinkhole = null;
    let op = null, ttl = null;

    if (!item.key.indexOf(hostPrefix)) {
        op = item.key.split(hostPrefix).pop();
        op = 'dst ' + op;
    }

    if (!item.key.indexOf(subnetPrefix)) {
        op = item.key.split(subnetPrefix).pop();
        op = 'dst net ' + op + '/24'
    }

    ttl = (item.value - Date.now()) + config.sinkholeTTL;

    console.log(ttl);

    if (ttl && ttl < 0)
        return db.del(item.key);

    if (op && ttl) {
        sentinel(op, ttl);
    }
})
.on('end', () => {
    ingestTorConsensus();
});

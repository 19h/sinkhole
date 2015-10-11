'use strict';

let childProcess = require('child_process');
let http = require('http');
let os = require('os');

let config = require('./config');

try {
    config = require('./config.local')
} catch (e) {
    console.log("Using default configuration! Copy config.js to config.local.js.");
}

let dry_run = process.env['DRY_RUN'];

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

/* feed local addresses into bloom filter */
let fi = os.networkInterfaces();

// flatten local interfaces
fi = Object.keys(fi)
.map((i) => fi[i].map((x) => x.address))
.reduce(((a, b) => a.concat(b)), []);

// learn local interfaces
fi.forEach((i) => wl.add(i));

let sentinel = (dst, ttl, isSubnet) => {
    if (isSubnet) {
        dst = 'dst net ' + dst + '/24';
    } else {
        dst = 'dst ' + dst;
    }

    if (dry_run) {
        console.log('tcpkill', ['-9', dst]);
    } else {
        let sinkhole = childProcess.spawn('tcpkill', ['-9', dst]);
    }

    setTimeout(() => {
        if (dry_run) {
            console.log('> SIGTERM tckill -9 dst ' + dst);
        } else {
            sinkhole.kill('SIGTERM');
        }
    }, ttl)
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

        console.log("Banning " + subnet + ".0/24..");

        db.put(subnetPrefix + subnet, {
            ts: Date.now(),
            sn: subnet
        }, () => {
            sentinel(subnet, config.sinkholeTTL, true, () => {
                db.del(hostPrefix + ip, () => {
                    delete hostBlacklist[ip];
                });
            });
        });
    };

    let blockHost = (ip) => {
        hostBlacklist[ip] = true;

        console.log("Banning " + ip + "..");

        db.put(hostPrefix + ip, {
            ts: Date.now(),
            ip: ip
        }, () => {
            sentinel(ip, config.sinkholeTTL, false, () => {
                db.del(hostPrefix + ip, () => {
                    delete hostBlacklist[ip];
                });
            });
        });
    };

    let lLbuf = config.host ? config.host.split('.').map((i) => Number(i)) : null;

    let hmap = {}; let metahmap = {};

    pcap_session.on('packet', (raw) => {
        let packet = pcap.decode.packet(raw);

        let data = packet.payload.payload;

        if (lLbuf !== null && beql(data.daddr.addr, lLbuf))
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
            /* already blocked || explicitly filtered || in bloom filter */
            if (hostBlacklist[ip] || ~config.hostWhitelist.indexOf(ip) || wl.has(ip))
                return;

            console.log('Detected portscan: ', ip, hmap[sub][id].join(', '));

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
};

let learnTorConsensus = (data) => {
    let hosts = {l:1}, subnets = {l:1};

    // feed into bloom filter
    data.forEach((i) => {
        // learn IP
        wl.add(i);

        hosts[i] ? ++hosts[i] : ((++hosts.l), (hosts[i] = 1));

        // learn /24
        let subnet = i.split('.').slice(0, 3).join('.');

        wl.add(subnet);

        subnets[subnet] ? ++subnets[subnet] : ((++subnets.l), (subnets[subnet] = 1));
    });

    // Fun: (top 10 subnets)
    // Object.keys(subnets).sort((s1, s2) => subnets[s2] - subnets[s1]).slice(0, 10)

    console.log("Learned about " + hosts.l + " hosts and " + subnets.l + " subnets.");

    hosts = undefined;
    subnets = undefined;

    init();
};

/* feed tor relays into bloom filter */
let ingestTorConsensus = () => {
    let start = Date.now();

    process.stdout.write("Downloading Tor consensus ..");

    let queueConsensusUpdate = (ttl) => {
        let restTTL = config.consensusMaxAge - (Date.now() - ttl);

        setTimeout(updateConsensus, restTTL < 0 ? 0 : restTTL);
    }

    let updateConsensus = () => {
        http.request('http://r3.geoca.st:9030/tor/status-vote/current/consensus', (sock) => {
            let data = Buffer(0), i = 0;

            sock.on('data', (chunk) => {
                i++ % 25 || process.stdout.write(".");

                data = Buffer.concat([data, chunk]);
            });

            sock.on('end', () => {
                process.stdout.write(" done (" + (Date.now() - start) + "ms).\n");

                data = data
                // convert buffer to string
                .toString()
                // split into lines
                .split("\n")
                // select lines starting with 'r '
                .filter((i) => i[0] === 'r' && i[1] === ' ')
                // extract IP in line
                .map((i) => i.split(' ')[6]);

                db.put('\xFFconsensus', {
                    data: data,
                    ts: Date.now()
                }, () => {
                    queueConsensusUpdate(Date.now());

                    learnTorConsensus(data);
                })
            });

            sock.on('error', () => {
                process.stdout.write(" failed, retrying..\n");
                
                ingestTorConsensus();
            })
        }).end();
    };

    db.get('\xFFconsensus', (err, data) => {
        if (err || (data && (Date.now() - data.ts) > config.consensusMaxAge))
            return updateConsensus();

        queueConsensusUpdate(data.ts);

        console.log(" done (using valid cache).");

        learnTorConsensus(data.data);
    });
};

/* feed history into bloom filter */
db.createReadStream()
.on('data', (item) => {
    // skip non-host&subnet keys
    if (item.key.indexOf('\xFFhost') && item.key.indexOf('\xFFsubnet'))
        return;

    console.log(item);

    let isSubnet = null;
    let op = null, ttl = null;

    if (!item.key.indexOf(hostPrefix)) {
        op = item.key.split(hostPrefix).pop();
    }

    if (!item.key.indexOf(subnetPrefix)) {
        isSubnet = true;
        op = item.key.split(subnetPrefix).pop();
    }

    ttl = (item.value.ts - Date.now()) + config.sinkholeTTL;

    if (~config.hostWhitelist.indexOf(op) || (ttl && ttl < 0))
        return db.del(item.key);

    if (op && ttl) {
        /* TOOD: what if this key is whitelisted since last ban? */
        sentinel(op, ttl, isSubnet);
    }
})
.on('end', () => {
    ingestTorConsensus();
});

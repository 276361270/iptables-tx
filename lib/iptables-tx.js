/*
 * iptables-tx.js: Batched iptables rules for node.js
 *
 * Inspired by https://github.com/pkrumins/node-iptables
 *
 * (C) 2013 Ken Perkins
 * MIT LICENSE
 *
 */

// Expose version through `pkginfo`.
require('pkginfo')(module, 'version');

var exec = require('child_process').exec,
    async = require('async'),
    _ = require('underscore');

var rules = exports.rules = {
        ACCEPT: 'ACCEPT',
        DROP: 'DROP',
        REJECT: 'REJECT'
    },
    chains = exports.chains = {
        INPUT:'INPUT',
        OUTPUT: 'OUTPUT',
        FORWARD: 'FORWARD'
    };

var Iptables = function(execFunction) {
    this._initialized = false;
    this._queue = [];

    this.exec = execFunction || exec;
};

Iptables.prototype.allow = function(rule, callback) {
    return this.newRule(rules.ACCEPT, rule.action || '-A', rule, callback);
};

Iptables.prototype.drop = function(rule, callback) {
    return this.newRule(rules.DROP, rule.action || '-A', rule, callback);
};

Iptables.prototype.reject = function(rule, callback) {
    return this.newRule(rules.REJECT, rule.action || '-A', rule, callback);
};

Iptables.prototype.policy = function(chain, target, callback) {
    return this.newRule(target, '-P', {
        chain: chain
    }, callback);
};

Iptables.prototype.flush = function(chain, callback) {
    return this.newRule(null, '-F', { chain: chain }, callback)
};

Iptables.prototype.init = function(forceInit) {

    if (!forceInit && this._queue.length > 0) {
        throw new Error('Can\'t initialize with entries in the queue without forcing');
    }

    this._initialized = true;
    this._queue = [];

    return this;
};

Iptables.prototype.commit = function(callback) {

    var self = this;

    if (!self._initialized) {
        callback('Please initialize before calling commit');
        return;
    }
    else if (!self._queue) {
        callback();
        return;
    }

    // setup an aggregation object
    var output = {
        success: []
    };

    async.forEachSeries(self._queue, function(rule, next) {
        self.execute(rule, function(err, results) {
            if (err) {
                output.failed = {
                    command: results.command,
                    stdout: results.stdout.toString(),
                    stderr: results.stderr.toString()
                };
            }
            else {
                output.success.push(results.command);
            }

            next(err);
        });
    }, function(err) {
        callback(err, output);
    });
};

Iptables.prototype.newRule = function(target, action, rule, callback) {

    rule.target = target;
    rule.action = action;
    rule.args = iptablesArgs(rule);

    if (typeof(callback) === 'function') {
        this.execute(rule, callback);
    }
    else if (this._initialized) {
        this._queue.push(rule);
    }
    else {
        throw new Error('Rules cannot be enqueued before init');
    }

    return this;

    function iptablesArgs(rule) {
        var args = [];

        if (!rule.chain) {
            rule.chain = chains.INPUT;
        }

        if (rule.action === '-P') {
            args = args.concat([rule.action, rule.chain, rule.target]);
            return args;
        }

        if (rule.chain) args = args.concat([rule.action, rule.chain]);
        if (rule.protocol) args = args.concat(["-p", rule.protocol]);
        if (rule.src) args = args.concat(["--src", rule.src]);
        if (rule.dst) args = args.concat(["--dst", rule.dst]);
        if (rule.sport) args = args.concat(["--sport", rule.sport]);
        if (rule.dport) args = args.concat(["--dport", rule.dport]);
        if (rule.in) args = args.concat(["-i", rule.in]);
        if (rule.out) args = args.concat(["-o", rule.out]);
        if (rule.target) args = args.concat(["-j", rule.target]);
        if (rule.list) args = args.concat(["-n", "-v"]);
        if (rule.tcpFlags) args = args.concat(['-m', 'tcp', '--tcp-flags', rule.tcpFlags.mask, rule.tcpFlags.comp]);
        if (rule.state) args = args.concat(["-m", "state", "--state", rule.state]);

        return args;
    }
};

Iptables.prototype.execute = function(rule, callback) {
    var cmd = ['iptables'].concat(rule.args);

    if (rule.sudo) {
        cmd = ['sudo'].concat(cmd);
    }

    this.exec(cmd.join(' '), function(err, stdout, stderr) {
        callback(err, {
            command: cmd.join(' '),
            stdout: stdout,
            stderr: stderr
        });
    });
};

exports.Iptables = Iptables;

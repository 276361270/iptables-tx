var iptables = require('../lib/iptables-tx'),
    Iptables = iptables.Iptables,
    rules = iptables.rules,
    chains = iptables.chains,
    should = require('should'),
    util = require('util');

describe('iptables-tx tests', function() {

    it('Instantiate the Iptables object', function(done) {
        var fw = new Iptables();

        should.exist(fw);
        fw._queue.should.eql([]);
        fw._initialized.should.equal(false);

        done();
    });

    it('Initialize the Iptables object', function(done) {
        var fw = new Iptables();

        should.exist(fw);
        fw._queue.should.eql([]);
        fw._initialized.should.equal(false);

        fw.init();

        fw._queue.should.eql([]);
        fw._initialized.should.equal(true);

        done();
    });

    it('Enqueue an allow rule', function(done) {
        var fw = new Iptables();

        should.exist(fw);
        fw._queue.should.eql([]);
        fw._initialized.should.equal(false);

        fw.init();

        fw._queue.should.eql([]);
        fw._initialized.should.equal(true);

        fw.allow({
            src: '0.0.0.0/0',
            dst: '192.168.10.1'
        });

        fw._queue.length.should.equal(1);
        fw._initialized.should.equal(true);

        done();
    });

    it('Enqueue a drop rule', function(done) {
        var fw = new Iptables();

        should.exist(fw);
        fw._queue.should.eql([]);
        fw._initialized.should.equal(false);

        fw.init();

        fw._queue.should.eql([]);
        fw._initialized.should.equal(true);

        fw.drop({
            src: '0.0.0.0/0',
            dst: '192.168.10.1'
        });

        fw._queue.length.should.equal(1);
        fw._initialized.should.equal(true);

        done();
    });

    it('Enqueue a reject rule', function(done) {
        var fw = new Iptables();

        should.exist(fw);
        fw._queue.should.eql([]);
        fw._initialized.should.equal(false);

        fw.init();

        fw._queue.should.eql([]);
        fw._initialized.should.equal(true);

        fw.reject({
            src: '0.0.0.0/0',
            dst: '192.168.10.1'
        });

        fw._queue.length.should.equal(1);
        fw._initialized.should.equal(true);

        done();
    });

    it('Enqueue a policy rule', function(done) {
        var fw = new Iptables();

        should.exist(fw);
        fw._queue.should.eql([]);
        fw._initialized.should.equal(false);

        fw.init();

        fw._queue.should.eql([]);
        fw._initialized.should.equal(true);

        fw.policy(chains.FORWARD, rules.ACCEPT);

        fw._queue.length.should.equal(1);
        fw._initialized.should.equal(true);

        done();
    });

    it('Enqueue a flush rule', function(done) {
        var fw = new Iptables();

        should.exist(fw);
        fw._queue.should.eql([]);
        fw._initialized.should.equal(false);

        fw.init();

        fw._queue.should.eql([]);
        fw._initialized.should.equal(true);

        fw.flush(chains.FORWARD);

        fw._queue.length.should.equal(1);
        fw._initialized.should.equal(true);

        done();
    });

    it('Enqueue a rule without init should fail', function(done) {
        var fw = new Iptables();

        should.exist(fw);
        fw._queue.should.eql([]);
        fw._initialized.should.equal(false);

        (function() {
            fw.reject({
                src: '0.0.0.0/0',
                dst: '192.168.10.1'
            });
        }).should.throw('Rules cannot be enqueued before init');

        done();
    });

    it('Init after enqueue should fail', function(done) {
        var fw = new Iptables();

        should.exist(fw);
        fw._queue.should.eql([]);
        fw._initialized.should.equal(false);

        fw.init();

        fw._queue.should.eql([]);
        fw._initialized.should.equal(true);

        fw.allow({
            src: '0.0.0.0/0',
            dst: '192.168.10.1'
        });


        (function() {
            fw.init();
        }).should.throw('Can\'t initialize with entries in the queue without forcing');

        done();
    });

    it('forced init after enqueue should succeed', function(done) {
        var fw = new Iptables();

        should.exist(fw);
        fw._queue.should.eql([]);
        fw._initialized.should.equal(false);

        fw.init();

        fw._queue.should.eql([]);
        fw._initialized.should.equal(true);

        fw.allow({
            src: '0.0.0.0/0',
            dst: '192.168.10.1'
        });

        (function() {
            fw.init(true);
        }).should.not.throw();

        fw._queue.should.eql([]);
        fw._initialized.should.equal(true);

        done();
    });

    it('can chain after init', function(done) {
        var fw = new Iptables();

        should.exist(fw);
        fw._queue.should.eql([]);
        fw._initialized.should.equal(false);

        var x = fw.init();

        x.should.equal(fw);
        done();
    });

    it('can chain after allow', function(done) {
        var fw = new Iptables();

        should.exist(fw);
        fw._queue.should.eql([]);
        fw._initialized.should.equal(false);

        fw.init();

        var x = fw.allow({
            src: '0.0.0.0/0',
            dst: '192.168.10.1'
        });

        x.should.equal(fw);
        done();
    })

    it('can chain after allow', function(done) {
        var fw = new Iptables();

        should.exist(fw);
        fw._queue.should.eql([]);
        fw._initialized.should.equal(false);

        fw.init();

        var x = fw.allow({
            src: '0.0.0.0/0',
            dst: '192.168.10.1'
        });

        x.should.equal(fw);
        done();
    });

    it('can chain after drop', function(done) {
        var fw = new Iptables();

        should.exist(fw);
        fw._queue.should.eql([]);
        fw._initialized.should.equal(false);

        fw.init();

        var x = fw.drop({
            src: '0.0.0.0/0',
            dst: '192.168.10.1'
        });

        x.should.equal(fw);
        done();
    });

    it('can chain after reject', function(done) {
        var fw = new Iptables();

        should.exist(fw);
        fw._queue.should.eql([]);
        fw._initialized.should.equal(false);

        fw.init();

        var x = fw.reject({
            src: '0.0.0.0/0',
            dst: '192.168.10.1'
        });

        x.should.equal(fw);
        done();
    });

    it('can chain after policy', function(done) {
        var fw = new Iptables();

        should.exist(fw);
        fw._queue.should.eql([]);
        fw._initialized.should.equal(false);

        fw.init();

        var x = fw.policy(chains.FORWARD, rules.ACCEPT);

        x.should.equal(fw);
        done();
    });

    it('can chain after flush', function(done) {
        var fw = new Iptables();

        should.exist(fw);
        fw._queue.should.eql([]);
        fw._initialized.should.equal(false);

        fw.init();

        var x = fw.flush(chains.FORWARD);

        x.should.equal(fw);
        done();
    });
});

var count = 0;
var fw = new Iptables(function(cmd, callback) {

    count++;
    console.log(cmd);
    callback(count % 5 === 0, count % 5 === 0 ? 'Unable to run command' : 'Success',
        count % 5 === 0 ? 'ERROR UNKNOWN' : '');
});

fw.init()
    .policy(chains.INPUT, rules.DROP)
    .policy(chains.FORWARD, rules.DROP)
    .policy(chains.OUTPUT, rules.ACCEPT)
    .flush(chains.INPUT)
    .flush(chains.FORWARD)
    .flush(chains.OUTPUT)
    .allow({
        src: '0.0.0.0/0',
        dst: '192.168.10.1'
    })
    .allow({
        src: '0.0.0.0/0',
        dst: '192.168.10.2'
    })
    .commit(function(err, output) {
        console.dir(err);
        console.dir(output);
    });
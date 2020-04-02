var node_sasl_wrapper = require('../');
var assert = require('assert');

describe('SaslWrapper', function() {
    it('should export a SaslWrapper', function() {
        var sasl = new node_sasl_wrapper.SaslWrapper();

        var connectResult = sasl.connect({
            service: 'zookeeper',
            serverFQDN: 'zookeeper.example',
            prompt_supp: {
                user: "bob",
                password: "bobsecret"
            }
        });
        assert.deepEqual(connectResult, {});

        var clientStartResult = sasl.clientStart({
            mechlist: 'DIGEST-MD5'
        });
        assert.equal(clientStartResult.mech, 'DIGEST-MD5');
        assert.equal(typeof clientStartResult.clientout, 'object');
        // DIGEST-MD5 starts empty.
        assert.equal(clientStartResult.clientout.length, 0);

        var clientStepResult = sasl.clientStep({
            serverin: Buffer.from('Hello!')
        });
        assert.equal(clientStepResult.error, 'authentication failure');
    });
});

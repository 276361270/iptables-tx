# iptables-tx

`iptables-tx` is a node.js package for dealing with iptables rules. The key feature
in this package is the ability to batch rule changes, and then commit them all
as a single async function with aggretate results.

## Attribution

This module is heavily inspired by Peteris Krumins's work on `node-iptables`[0]

[0] https://github.com/pkrumins/node-iptables
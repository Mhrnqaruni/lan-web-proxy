"use strict";

const assert = require("node:assert/strict");
const ip = require("../vendor/ip");

assert.equal(ip.toBuffer("127.0.0.1").toString("hex"), "7f000001");
assert.equal(ip.toBuffer("::1").toString("hex"), "00000000000000000000000000000001");
assert.equal(ip.toBuffer("::ffff:192.0.2.10").toString("hex"), "00000000000000000000ffffc000020a");
assert.equal(ip.isV4Format("192.168.1.1"), true);
assert.equal(ip.isV4Format("999.1.1.1"), false);
assert.equal(ip.isV6Format("2001:db8::1"), true);
assert.throws(() => ip.toBuffer("not-an-address"));

console.log("IP compatibility shim tests passed.");

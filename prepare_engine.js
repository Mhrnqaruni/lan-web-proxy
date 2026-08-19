"use strict";

// Rammerhead ships patched browser assets. When its Hammerhead dependency is
// updated for security fixes, rebuild those assets from the exact installed
// version so the browser and server protocols remain in sync.
const fs = require("node:fs");
const path = require("node:path");

const rammerheadPackage = require.resolve("rammerhead/package.json");
const hammerheadPackage = require.resolve("testcafe-hammerhead/package.json");
const rammerheadRoot = path.dirname(rammerheadPackage);
const hammerheadRoot = path.dirname(hammerheadPackage);
const rammerheadVersion = require(rammerheadPackage).version;
const hammerheadVersion = require(hammerheadPackage).version;
const browserPatchVersion = "lan-storage-api-tls-2";
const buildIdentity = `${rammerheadVersion}/${hammerheadVersion}/${browserPatchVersion}`;
const marker = path.join(rammerheadRoot, "src", "client", ".lan-proxy-build-version");

// Rammerhead 1.2.64 forwards `ssl` only in its single-port branch. Hammerhead
// itself supports two HTTPS listeners, so retain the option in the normal
// two-port branch as well. This is kept here so a clean npm install is patched
// deterministically before the engine is loaded.
const proxySourcePath = path.join(rammerheadRoot, "src", "classes", "RammerheadProxy.js");
let proxySource = fs.readFileSync(proxySourcePath, "utf8");
const originalProxySource = proxySource;
if (!proxySource.includes("port2: crossDomainPort,\n                ssl")) {
  proxySource = proxySource.replace(
    "port2: crossDomainPort\n            });",
    "port2: crossDomainPort,\n                ssl\n            });",
  );
  if (!proxySource.includes("port2: crossDomainPort,\n                ssl")) {
    throw new Error("Could not apply the Rammerhead two-port TLS patch.");
  }
}
if (!proxySource.includes("const net = require('net');")) {
  proxySource = proxySource.replace("const http = require('http');", "const http = require('http');\nconst net = require('net');");
}
proxySource = proxySource.replaceAll("http.Server.prototype.listen", "net.Server.prototype.listen");
if (proxySource !== originalProxySource) fs.writeFileSync(proxySourcePath, proxySource, "utf8");

try {
  if (fs.readFileSync(marker, "utf8").trim() === buildIdentity) process.exit(0);
} catch (error) {
  if (error.code !== "ENOENT") throw error;
}

const nestedModules = path.join(rammerheadRoot, "node_modules");
const nestedHammerhead = path.join(nestedModules, "testcafe-hammerhead");
fs.mkdirSync(nestedModules, { recursive: true });
if (!fs.existsSync(nestedHammerhead)) {
  fs.symlinkSync(hammerheadRoot, nestedHammerhead, "junction");
}

console.log(`Preparing Rammerhead browser assets for TestCafe Hammerhead ${hammerheadVersion}…`);
const rammerheadClient = path.join(rammerheadRoot, "src", "client", "rammerhead.js");
const originalClientSource = fs.readFileSync(rammerheadClient, "utf8");
const storageCompatibilitySource = originalClientSource.replace(
  "var proxiedLocalStorage = localStorage;",
  "var proxiedLocalStorage = hammerhead.storages.localStorageProxy; " +
    "if (proxiedLocalStorage && typeof proxiedLocalStorage.unwrapProxy === 'function') " +
    "proxiedLocalStorage = proxiedLocalStorage.unwrapProxy();",
);
if (!storageCompatibilitySource.includes("hammerhead.storages.localStorageProxy")) {
  throw new Error("Could not apply the Rammerhead storage compatibility patch.");
}
fs.writeFileSync(rammerheadClient, storageCompatibilitySource, "utf8");
require(path.join(rammerheadRoot, "src", "build.js"));
fs.writeFileSync(marker, `${buildIdentity}\n`, "utf8");

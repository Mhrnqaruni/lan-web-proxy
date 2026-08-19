"use strict";

// Rammerhead includes sticky-session-custom, which only uses ip.toBuffer().
// The upstream `ip` package has no patched release for GHSA-2p57-rm9w-gvfp.
// This small, strict parser supplies the required API without the vulnerable
// public/private address classification functions.

function parseIPv4(value) {
  const parts = value.split(".");
  if (parts.length !== 4) throw new Error("Invalid IPv4 address");
  const bytes = parts.map((part) => {
    if (!/^(?:0|[1-9][0-9]{0,2})$/.test(part)) throw new Error("Invalid IPv4 address");
    const byte = Number(part);
    if (byte > 255) throw new Error("Invalid IPv4 address");
    return byte;
  });
  return Buffer.from(bytes);
}

function parseIPv6(value) {
  let address = value.toLowerCase();
  const zoneIndex = address.indexOf("%");
  if (zoneIndex !== -1) address = address.slice(0, zoneIndex);

  if (address.includes(".")) {
    const separator = address.lastIndexOf(":");
    if (separator === -1) throw new Error("Invalid IPv6 address");
    const ipv4 = parseIPv4(address.slice(separator + 1));
    const high = ipv4.readUInt16BE(0).toString(16);
    const low = ipv4.readUInt16BE(2).toString(16);
    address = `${address.slice(0, separator)}:${high}:${low}`;
  }

  const halves = address.split("::");
  if (halves.length > 2) throw new Error("Invalid IPv6 address");
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) {
    throw new Error("Invalid IPv6 address");
  }

  const groups = [...left, ...Array(missing).fill("0"), ...right];
  if (groups.length !== 8 || groups.some((group) => !/^[0-9a-f]{1,4}$/.test(group))) {
    throw new Error("Invalid IPv6 address");
  }
  const result = Buffer.alloc(16);
  groups.forEach((group, index) => result.writeUInt16BE(Number.parseInt(group, 16), index * 2));
  return result;
}

function toBuffer(value, destination, offset = 0) {
  const address = String(value);
  const parsed = address.includes(":") ? parseIPv6(address) : parseIPv4(address);
  if (!destination) return parsed;
  parsed.copy(destination, offset);
  return destination;
}

module.exports = {
  isV4Format(value) {
    try {
      parseIPv4(String(value));
      return true;
    } catch {
      return false;
    }
  },
  isV6Format(value) {
    try {
      parseIPv6(String(value));
      return true;
    } catch {
      return false;
    }
  },
  toBuffer,
};

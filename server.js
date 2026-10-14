import net from "node:net";
import dns from "node:dns";
import { createHash, timingSafeEqual } from "node:crypto";

// ---------------------------------------------------------------- settings

const SOCKS_PORT = Number(process.env.SOCKS_PORT) || 1080;
const SOCKS_USER = process.env.SOCKS_USER || "";
const SOCKS_PASS = process.env.SOCKS_PASS || "";
const AUTH_REQUIRED = Boolean(SOCKS_USER && SOCKS_PASS);

// Running without credentials makes this an open proxy for the whole internet, so it now has to
// be requested explicitly.
const ALLOW_OPEN = process.env.ALLOW_OPEN === "1";
// Only for local tests: allow loopback / private destinations.
const ALLOW_PRIVATE = process.env.ALLOW_PRIVATE_DESTINATIONS === "1";

const MAX_CONNECTIONS = Number(process.env.MAX_CONNECTIONS) || 400;
const HANDSHAKE_TIMEOUT_MS = Number(process.env.HANDSHAKE_TIMEOUT_MS) || 10000;
const CONNECT_TIMEOUT_MS = Number(process.env.CONNECT_TIMEOUT_MS) || 10000;
const DNS_TIMEOUT_MS = Number(process.env.DNS_TIMEOUT_MS) || 5000;
const IDLE_TIMEOUT_MS = Number(process.env.IDLE_TIMEOUT_MS) || 300000;

// Ports that cause most abuse complaints (mail spam, SMB/RDP/telnet scanning).
const DEFAULT_BLOCKED_PORTS = [23, 25, 135, 137, 138, 139, 445, 465, 587, 2525, 3389];

function parseBlockedPorts(raw) {
  const value = (raw || "").trim();
  if (!value) return new Set(DEFAULT_BLOCKED_PORTS);
  if (value.toLowerCase() === "none") return new Set();
  return new Set(
    value
      .split(",")
      .map((s) => Number(s.trim()))
      .filter((p) => Number.isInteger(p) && p > 0 && p < 65536)
  );
}
const BLOCKED_PORTS = parseBlockedPorts(process.env.BLOCKED_PORTS);

if (!AUTH_REQUIRED && !ALLOW_OPEN) {
  console.error("refusing to start: SOCKS_USER and SOCKS_PASS are not set (set ALLOW_OPEN=1 only if you really want an open proxy)");
  process.exit(1);
}

// ---------------------------------------------------------------- helpers

const sha256 = (value) => createHash("sha256").update(value, "utf8").digest();
const safeEqual = (a, b) => timingSafeEqual(sha256(a), sha256(b));
const delay = (ms) => new Promise((r) => setTimeout(r, ms));

function isPrivateIPv4(parts) {
  const [a, b, c] = parts;
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT / Railway internal
  if (a === 169 && b === 254) return true; // link-local, cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 192 && b === 0 && c === 0) return true;
  if (a === 198 && (b === 18 || b === 19)) return true;
  return a >= 224;
}

function isPrivateIPv6(addr) {
  const h = addr.toLowerCase().split("%")[0];
  if (h === "::" || h === "::1") return true;
  const dotted = /^::ffff:(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(h);
  if (dotted) return isPrivateIPv4(dotted.slice(1).map(Number));
  const hex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(h);
  if (hex) {
    const hi = parseInt(hex[1], 16);
    const lo = parseInt(hex[2], 16);
    return isPrivateIPv4([hi >> 8, hi & 255, lo >> 8, lo & 255]);
  }
  const first = parseInt(h.split(":")[0] || "0", 16);
  if ((first & 0xfe00) === 0xfc00) return true; // fc00::/7  (includes Railway fd12:: private net)
  if ((first & 0xffc0) === 0xfe80) return true; // fe80::/10
  return (first & 0xff00) === 0xff00; // multicast
}

function isPrivateAddress(ip) {
  if (net.isIPv4(ip)) return isPrivateIPv4(ip.split(".").map(Number));
  if (net.isIPv6(ip)) return isPrivateIPv6(ip);
  return true;
}

function forbiddenName(host) {
  const h = host.toLowerCase().replace(/\.$/, "");
  return (
    h === "localhost" ||
    h.endsWith(".localhost") ||
    h.endsWith(".local") ||
    h.endsWith(".internal") ||
    h.endsWith(".localdomain")
  );
}

// Resolves the destination ourselves and returns the address we are allowed to connect to.
// Connecting to the validated address (not the name) also closes the DNS-rebinding gap.
async function resolveAllowed(host) {
  if (net.isIP(host)) {
    if (!ALLOW_PRIVATE && isPrivateAddress(host)) return { error: 2 };
    return { address: host, family: net.isIPv6(host) ? 6 : 4 };
  }
  if (!ALLOW_PRIVATE && forbiddenName(host)) return { error: 2 };
  let records;
  try {
    records = await Promise.race([
      dns.promises.lookup(host, { all: true, verbatim: true }),
      delay(DNS_TIMEOUT_MS).then(() => {
        throw Object.assign(new Error("dns timeout"), { code: "ETIMEDOUT" });
      }),
    ]);
  } catch (err) {
    return { error: err && err.code === "ETIMEDOUT" ? 6 : 4 };
  }
  const usable = records.filter((r) => ALLOW_PRIVATE || !isPrivateAddress(r.address));
  if (!usable.length) return { error: 2 };
  usable.sort((a, b) => a.family - b.family); // IPv4 first: many hosts have no IPv6 egress
  return { address: usable[0].address, family: usable[0].family };
}

function replyCode(err) {
  switch (err && err.code) {
    case "ECONNREFUSED":
      return 5;
    case "ETIMEDOUT":
      return 6;
    case "ENETUNREACH":
      return 3;
    case "EHOSTUNREACH":
    case "ENOTFOUND":
    case "EAI_AGAIN":
      return 4;
    default:
      return 1;
  }
}

const reply = (code) => Buffer.from([5, code, 0, 1, 0, 0, 0, 0, 0, 0]);

// Buffered reader with a single permanent listener (no data can slip through between reads).
class ByteReader {
  constructor(socket) {
    this.socket = socket;
    this.buf = Buffer.alloc(0);
    this.pending = null;
    this.closed = false;
    this.onData = (chunk) => {
      this.buf = Buffer.concat([this.buf, chunk]);
      if (this.buf.length > 4096 && this.pending === null) {
        this.closed = true;
        socket.destroy();
      }
      this.flush();
    };
    this.onEnd = () => {
      this.closed = true;
      this.flush();
    };
    socket.on("data", this.onData);
    socket.on("end", this.onEnd);
    socket.on("close", this.onEnd);
    socket.on("error", this.onEnd);
  }
  flush() {
    if (!this.pending) return;
    const { n, resolve, reject } = this.pending;
    if (this.buf.length >= n) {
      const out = this.buf.subarray(0, n);
      this.buf = this.buf.subarray(n);
      this.pending = null;
      resolve(out);
    } else if (this.closed) {
      this.pending = null;
      reject(new Error("client closed"));
    }
  }
  read(n) {
    return new Promise((resolve, reject) => {
      this.pending = { n, resolve, reject };
      this.flush();
    });
  }
  // Stops reading and hands back whatever was already received.
  detach() {
    this.socket.off("data", this.onData);
    this.socket.off("end", this.onEnd);
    this.socket.off("close", this.onEnd);
    this.socket.off("error", this.onEnd);
    this.socket.pause();
    const rest = this.buf;
    this.buf = Buffer.alloc(0);
    return rest;
  }
}

// ---------------------------------------------------------------- connection handling

let recentAuthFailures = 0;
setInterval(() => {
  recentAuthFailures = 0;
}, 60000).unref();

async function handleConnection(client) {
  client.on("error", () => {});
  client.setNoDelay(true);
  const reader = new ByteReader(client);
  const handshakeTimer = setTimeout(() => client.destroy(), HANDSHAKE_TIMEOUT_MS);

  try {
    let head = await reader.read(2);
    if (head[0] !== 5) {
      client.destroy();
      return;
    }
    const methods = Array.from(await reader.read(head[1]));

    if (AUTH_REQUIRED) {
      if (!methods.includes(2)) {
        client.end(Buffer.from([5, 0xff]));
        return;
      }
      client.write(Buffer.from([5, 2]));

      head = await reader.read(2);
      if (head[0] !== 1) {
        client.destroy();
        return;
      }
      const uname = (await reader.read(head[1])).toString("utf8");
      const plen = (await reader.read(1))[0];
      const passwd = (await reader.read(plen)).toString("utf8");

      const ok = safeEqual(uname, SOCKS_USER) && safeEqual(passwd, SOCKS_PASS);
      if (!ok) {
        recentAuthFailures++;
        clearTimeout(handshakeTimer); // the delay below is bounded (max 5s) and must not be cut short
        // slow down guessing; the delay grows while failures keep coming
        await delay(1000 + Math.min(recentAuthFailures * 100, 4000));
        client.end(Buffer.from([1, 1]));
        return;
      }
      client.write(Buffer.from([1, 0]));
    } else {
      if (!methods.includes(0)) {
        client.end(Buffer.from([5, 0xff]));
        return;
      }
      client.write(Buffer.from([5, 0]));
    }

    const req = await reader.read(4);
    if (req[0] !== 5 || req[1] !== 1) {
      client.end(reply(7));
      return;
    }
    const atyp = req[3];
    let host;
    if (atyp === 1) {
      host = Array.from(await reader.read(4)).join(".");
    } else if (atyp === 4) {
      const raw = await reader.read(16);
      const parts = [];
      for (let i = 0; i < 16; i += 2) parts.push(raw.readUInt16BE(i).toString(16));
      host = parts.join(":");
    } else if (atyp === 3) {
      const len = (await reader.read(1))[0];
      host = (await reader.read(len)).toString("utf8");
    } else {
      client.end(reply(8));
      return;
    }
    const port = (await reader.read(2)).readUInt16BE(0);
    clearTimeout(handshakeTimer);

    if (!host || BLOCKED_PORTS.has(port)) {
      client.end(reply(2));
      return;
    }
    const target = await resolveAllowed(host);
    if (target.error) {
      client.end(reply(target.error));
      return;
    }

    const leftover = reader.detach();
    const upstream = net.connect({ host: target.address, port, family: target.family });
    upstream.setNoDelay(true);
    upstream.setTimeout(CONNECT_TIMEOUT_MS);

    let connected = false;
    const closeBoth = () => {
      client.destroy();
      upstream.destroy();
    };
    upstream.on("error", (err) => {
      if (!connected && !client.destroyed) client.end(reply(replyCode(err)));
      closeBoth();
    });
    upstream.on("timeout", () => {
      if (!connected && !client.destroyed) client.end(reply(6));
      closeBoth();
    });
    upstream.on("close", closeBoth);
    client.on("close", closeBoth);

    upstream.on("connect", () => {
      connected = true;
      upstream.setTimeout(IDLE_TIMEOUT_MS);
      client.setTimeout(IDLE_TIMEOUT_MS);
      client.on("timeout", closeBoth);
      client.write(reply(0));
      if (leftover.length) upstream.write(leftover);
      client.pipe(upstream);
      upstream.pipe(client);
      client.resume();
    });
  } catch {
    clearTimeout(handshakeTimer);
    client.destroy();
  }
}

// ---------------------------------------------------------------- server

const server = net.createServer(handleConnection);
server.maxConnections = MAX_CONNECTIONS;
server.on("error", (err) => {
  console.error(`server error: ${err && err.message}`);
  process.exit(1);
});
server.listen(SOCKS_PORT, () => {
  if (!AUTH_REQUIRED) console.log("warning: ALLOW_OPEN=1, relay is running without authentication");
  console.log(`socks5 relay listening on ${SOCKS_PORT}`);
});

// Railway sends SIGTERM when it replaces the container.
function shutdown() {
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 5000).unref();
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

// A single bad connection must never take the relay down.
process.on("uncaughtException", (err) => console.error(`uncaught: ${err && err.message}`));
process.on("unhandledRejection", (err) => console.error(`unhandled: ${err && err.message}`));

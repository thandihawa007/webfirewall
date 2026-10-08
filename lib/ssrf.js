const dns = require('dns').promises;
const net = require('net');
const { URL } = require('url');

/**
 * Checks whether an IPv4 address string falls into private, loopback, or reserved ranges.
 */
function isPrivateIPv4(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) {
    return true; // Malformed = reject
  }

  const [a, b, c, d] = parts;

  // 0.0.0.0/8 (Current network)
  if (a === 0) return true;

  // 10.0.0.0/8 (Private A)
  if (a === 10) return true;

  // 127.0.0.0/8 (Loopback)
  if (a === 127) return true;

  // 169.254.0.0/16 (Link-local)
  if (a === 169 && b === 254) return true;

  // 172.16.0.0/12 (Private B: 172.16.0.0 - 172.31.255.255)
  if (a === 172 && b >= 16 && b <= 31) return true;

  // 192.168.0.0/16 (Private C)
  if (a === 192 && b === 168) return true;

  // 100.64.0.0/10 (Carrier-Grade NAT)
  if (a === 100 && b >= 64 && b <= 127) return true;

  // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (TEST-NET)
  if (a === 192 && b === 0 && c === 2) return true;
  if (a === 198 && b === 51 && c === 100) return true;
  if (a === 203 && b === 0 && c === 113) return true;

  // 224.0.0.0/4 (Multicast) & 240.0.0.0/4 (Reserved)
  if (a >= 224) return true;

  // Broadcast
  if (a === 255 && b === 255 && c === 255 && d === 255) return true;

  return false;
}

/**
 * Checks whether an IPv6 address string falls into private, loopback, or reserved ranges.
 */
function isPrivateIPv6(ip) {
  const normalized = ip.toLowerCase();

  // Loopback ::1 & unspecified ::
  if (normalized === '::1' || normalized === '::' || normalized === '0:0:0:0:0:0:0:1' || normalized === '0:0:0:0:0:0:0:0') {
    return true;
  }

  // IPv4-mapped IPv6 (::ffff:127.0.0.1, etc.)
  if (normalized.startsWith('::ffff:')) {
    const v4Part = normalized.slice(7);
    return isPrivateIPv4(v4Part);
  }

  // Unique local addresses (fc00::/7)
  if (normalized.startsWith('fc') || normalized.startsWith('fd')) {
    return true;
  }

  // Link-local addresses (fe80::/10)
  if (normalized.startsWith('fe8') || normalized.startsWith('fe9') || normalized.startsWith('fea') || normalized.startsWith('feb')) {
    return true;
  }

  return false;
}

function isPrivateOrReservedIP(ip) {
  if (!ip || typeof ip !== 'string') return true;
  if (ip.includes(':')) {
    return isPrivateIPv6(ip);
  }
  return isPrivateIPv4(ip);
}

/**
 * Validates a target URL against SSRF protection policies:
 * 1. Must use http:// or https:// protocol.
 * 2. Hostname must not be 'localhost' or a reserved name.
 * 3. Hostname must resolve via DNS to a public, non-reserved IP.
 *
 * @param {string} targetUrl
 * @returns {Promise<{ valid: boolean, error?: string, resolvedIps?: string[] }>}
 */
async function validateTargetUrl(targetUrl) {
  if (!targetUrl || typeof targetUrl !== 'string') {
    return { valid: false, error: 'Target URL is required' };
  }

  let parsed;
  try {
    parsed = new URL(targetUrl);
  } catch (_) {
    return { valid: false, error: 'Invalid URL format' };
  }

  // 1. Enforce http / https protocols
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { valid: false, error: 'Only HTTP and HTTPS protocols are supported' };
  }

  const hostname = parsed.hostname.toLowerCase();

  // 2. Reject explicit localhost and common local domain names
  if (
    hostname === 'localhost' ||
    hostname.endsWith('.localhost') ||
    hostname.endsWith('.local') ||
    hostname.endsWith('.internal')
  ) {
    return { valid: false, error: 'Target URL cannot be localhost or an internal hostname' };
  }

  // 3. If hostname is directly an IP literal, validate immediately
  const ipType = net.isIP(hostname);
  if (ipType !== 0 && isPrivateOrReservedIP(hostname)) {
    return { valid: false, error: 'Target URL resolves to a private or loopback IP address (SSRF blocked)' };
  }

  // 4. Perform DNS lookup to inspect resolved IPs
  try {
    const results = await dns.lookup(hostname, { all: true });
    if (!results || results.length === 0) {
      return { valid: false, error: 'Could not resolve hostname' };
    }

    const resolvedIps = results.map(r => r.address);
    for (const ip of resolvedIps) {
      if (isPrivateOrReservedIP(ip)) {
        return {
          valid: false,
          error: `Target host resolved to prohibited private IP (${ip}) (SSRF blocked)`
        };
      }
    }

    return { valid: true, resolvedIps };
  } catch (err) {
    return { valid: false, error: `DNS resolution failed: ${err.message}` };
  }
}

module.exports = {
  isPrivateOrReservedIP,
  validateTargetUrl
};

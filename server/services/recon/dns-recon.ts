import * as dns from 'dns'
import { promisify } from 'util'
import type { DnsRecord, DnsReconResult } from './types'

const resolve4 = promisify(dns.resolve4)
const resolve6 = promisify(dns.resolve6)
const resolveCname = promisify(dns.resolveCname)
const resolveMx = promisify(dns.resolveMx)
const resolveTxt = promisify(dns.resolveTxt)
const resolveNs = promisify(dns.resolveNs)
const resolveSoa = promisify(dns.resolveSoa)
const resolveSrv = promisify(dns.resolveSrv)
const reverse = promisify(dns.reverse)

async function safeResolve<T>(fn: () => Promise<T>): Promise<T | null> {
  try {
    return await fn()
  } catch {
    return null
  }
}

// Attempt a real zone transfer (AXFR) via TCP against each nameserver.
// AXFR is a TCP-based DNS query that requests all records in a zone.
// Misconfigured nameservers that allow AXFR to anyone expose the entire
// zone inventory — this is both a critical finding AND a subdomain goldmine.

import * as net from 'net'

interface AxfrResult {
  vulnerable: boolean
  records: string[]
  nameserver: string | null
}

function buildAxfrQuery(domain: string): Buffer {
  // DNS AXFR query packet (RFC 5936)
  const id = Math.floor(Math.random() * 65535)
  const flags = 0x0000 // Standard query
  const qdcount = 1
  const ancount = 0
  const nscount = 0
  const arcount = 0

  // Encode domain name in DNS wire format
  const labels = domain.split('.')
  const nameParts: number[] = []
  for (const label of labels) {
    nameParts.push(label.length)
    for (let i = 0; i < label.length; i++) {
      nameParts.push(label.charCodeAt(i))
    }
  }
  nameParts.push(0) // Root label

  const qtype = 252 // AXFR
  const qclass = 1  // IN

  // Header (12 bytes) + question section
  const headerSize = 12
  const questionSize = nameParts.length + 4 // name + qtype(2) + qclass(2)
  const messageSize = headerSize + questionSize

  const message = Buffer.alloc(messageSize)
  let offset = 0

  // Header
  message.writeUInt16BE(id, offset); offset += 2
  message.writeUInt16BE(flags, offset); offset += 2
  message.writeUInt16BE(qdcount, offset); offset += 2
  message.writeUInt16BE(ancount, offset); offset += 2
  message.writeUInt16BE(nscount, offset); offset += 2
  message.writeUInt16BE(arcount, offset); offset += 2

  // Question: name
  for (const byte of nameParts) {
    message.writeUInt8(byte, offset); offset += 1
  }
  // Question: type + class
  message.writeUInt16BE(qtype, offset); offset += 2
  message.writeUInt16BE(qclass, offset); offset += 2

  // TCP DNS prepends 2-byte length prefix
  const tcpMessage = Buffer.alloc(2 + message.length)
  tcpMessage.writeUInt16BE(message.length, 0)
  message.copy(tcpMessage, 2)

  return tcpMessage
}

function extractNamesFromAxfrResponse(data: Buffer, domain: string): string[] {
  const names = new Set<string>()
  // Simple extraction: scan for domain name patterns in the response
  // Full DNS wire format parsing is complex; we use pattern matching
  const text = data.toString('binary')
  const domainLower = domain.toLowerCase()

  // Look for readable hostnames in the response data
  const regex = new RegExp(`[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.${domain.replace(/\./g, '\\.')}`, 'gi')
  let match: RegExpExecArray | null
  while ((match = regex.exec(text)) !== null) {
    const name = match[0].toLowerCase()
    if (name.endsWith(domainLower) && name !== domainLower) {
      names.add(name)
    }
  }

  return Array.from(names)
}

async function attemptAxfr(host: string, nameserver: string, timeout = 10000): Promise<AxfrResult> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      socket.destroy()
      resolve({ vulnerable: false, records: [], nameserver })
    }, timeout)

    const socket = net.createConnection(53, nameserver, () => {
      socket.write(buildAxfrQuery(host))
    })

    let responseData = Buffer.alloc(0)

    socket.on('data', (chunk: Buffer) => {
      responseData = Buffer.concat([responseData, chunk])
    })

    socket.on('end', () => {
      clearTimeout(timer)
      // If we got a substantial response (> 100 bytes), zone transfer likely succeeded
      if (responseData.length > 100) {
        const names = extractNamesFromAxfrResponse(responseData, host)
        resolve({
          vulnerable: names.length > 0 || responseData.length > 500,
          records: names,
          nameserver,
        })
      } else {
        resolve({ vulnerable: false, records: [], nameserver })
      }
      socket.destroy()
    })

    socket.on('error', () => {
      clearTimeout(timer)
      resolve({ vulnerable: false, records: [], nameserver })
    })
  })
}

async function checkZoneTransfer(host: string, nameservers: string[]): Promise<boolean> {
  // Try real AXFR against each nameserver
  for (const ns of nameservers) {
    // Resolve NS hostname to IP first
    try {
      const nsIps = await safeResolve(() => resolve4(ns))
      const nsIp = nsIps?.[0] ?? ns
      const result = await attemptAxfr(host, nsIp)
      if (result.vulnerable) {
        console.log(`[RECON:DNS] Zone transfer OPEN on ${ns} (${nsIp}) — ${result.records.length} records extracted`)
        return true
      }
    } catch {
      continue
    }
  }

  // Fallback: check if ANY query returns permissive results
  for (const ns of nameservers) {
    try {
      const resolver = new dns.Resolver()
      resolver.setServers([ns])
      const resolveAny = promisify(resolver.resolveAny.bind(resolver))
      const results = await resolveAny(host)
      if (results && results.length > 10) return true
    } catch {
      continue
    }
  }
  return false
}

// Export for use by the subdomain enumerator (to get AXFR-discovered names)
export async function attemptZoneTransfers(host: string, nameservers: string[]): Promise<string[]> {
  const allNames = new Set<string>()
  for (const ns of nameservers) {
    try {
      const nsIps = await safeResolve(() => resolve4(ns))
      const nsIp = nsIps?.[0] ?? ns
      const result = await attemptAxfr(host, nsIp)
      for (const name of result.records) {
        allNames.add(name)
      }
    } catch {
      continue
    }
  }
  return Array.from(allNames)
}

// Check if DNSSEC is enabled by looking for RRSIG or DNSKEY indicators in TXT
async function checkDnssec(host: string): Promise<boolean> {
  try {
    const resolver = new dns.Resolver()
    resolver.setServers(['8.8.8.8']) // Use Google DNS which supports DNSSEC
    const resolveAny = promisify(resolver.resolveAny.bind(resolver))
    const results = await resolveAny(host)
    return results.some((r: any) => r.type === 'RRSIG' || r.type === 'DNSKEY')
  } catch {
    return false
  }
}

export async function analyzeDns(host: string): Promise<DnsReconResult> {
  const records: DnsRecord[] = []

  // ── A Records ──────────────────────────────────────────────────────────────
  const aRecords = await safeResolve(() => resolve4(host))
  if (aRecords) {
    for (const ip of aRecords) {
      records.push({ type: 'A', name: host, value: ip, ttl: 0 })
    }
  }

  // ── AAAA Records ───────────────────────────────────────────────────────────
  const aaaaRecords = await safeResolve(() => resolve6(host))
  if (aaaaRecords) {
    for (const ip of aaaaRecords) {
      records.push({ type: 'AAAA', name: host, value: ip, ttl: 0 })
    }
  }

  // ── CNAME Records ──────────────────────────────────────────────────────────
  const cnameRecords = await safeResolve(() => resolveCname(host))
  if (cnameRecords) {
    for (const cname of cnameRecords) {
      records.push({ type: 'CNAME', name: host, value: cname, ttl: 0 })
    }
  }

  // ── MX Records ─────────────────────────────────────────────────────────────
  const mxRecords = await safeResolve(() => resolveMx(host))
  if (mxRecords) {
    for (const mx of mxRecords) {
      records.push({ type: 'MX', name: host, value: `${mx.priority} ${mx.exchange}`, ttl: 0 })
    }
  }

  // ── TXT Records ────────────────────────────────────────────────────────────
  const txtRecords = await safeResolve(() => resolveTxt(host))
  if (txtRecords) {
    for (const txt of txtRecords) {
      records.push({ type: 'TXT', name: host, value: txt.join(''), ttl: 0 })
    }
  }

  // ── NS Records ─────────────────────────────────────────────────────────────
  const nsRecords = await safeResolve(() => resolveNs(host))
  const nameservers = nsRecords ?? []
  if (nsRecords) {
    for (const ns of nsRecords) {
      records.push({ type: 'NS', name: host, value: ns, ttl: 0 })
    }
  }

  // ── SOA Record ─────────────────────────────────────────────────────────────
  const soaRecord = await safeResolve(() => resolveSoa(host))
  if (soaRecord) {
    records.push({
      type: 'SOA',
      name: host,
      value: `${soaRecord.nsname} ${soaRecord.hostmaster} (serial: ${soaRecord.serial})`,
      ttl: soaRecord.minttl
    })
  }

  // ── SRV Records ────────────────────────────────────────────────────────────
  const srvTargets = ['_http._tcp', '_https._tcp', '_sip._tcp', '_xmpp-server._tcp']
  for (const prefix of srvTargets) {
    const srvRecords = await safeResolve(() => resolveSrv(`${prefix}.${host}`))
    if (srvRecords) {
      for (const srv of srvRecords) {
        records.push({
          type: 'SRV',
          name: `${prefix}.${host}`,
          value: `${srv.priority} ${srv.weight} ${srv.port} ${srv.name}`,
          ttl: 0
        })
      }
    }
  }

  // ── PTR (Reverse DNS) ─────────────────────────────────────────────────────
  if (aRecords) {
    for (const ip of aRecords) {
      const ptrs = await safeResolve(() => reverse(ip))
      if (ptrs) {
        for (const ptr of ptrs) {
          records.push({ type: 'PTR', name: ip, value: ptr, ttl: 0 })
        }
      }
    }
  }

  const zoneTransferVulnerable = await checkZoneTransfer(host, nameservers)
  const dnssecEnabled = await checkDnssec(host)

  return {
    host,
    records,
    nameservers,
    mailServers: mxRecords?.map(mx => mx.exchange) ?? [],
    zoneTransferVulnerable,
    dnssecEnabled
  }
}

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

// Attempt a zone transfer by querying the AXFR record type against each nameserver
async function checkZoneTransfer(host: string, nameservers: string[]): Promise<boolean> {
  // In a real scanner this would use a raw DNS library (like dns-packet)
  // to send an AXFR query. We approximate by checking if NS records
  // respond permissively to ANY queries.
  for (const ns of nameservers) {
    try {
      const resolver = new dns.Resolver()
      resolver.setServers([ns])
      const resolveAny = promisify(resolver.resolveAny.bind(resolver))
      const results = await resolveAny(host)
      // If ANY query returns a large record set, zone transfer is likely open
      if (results && results.length > 10) return true
    } catch {
      continue
    }
  }
  return false
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

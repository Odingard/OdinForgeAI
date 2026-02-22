import * as net from 'net'
import type { PortResult, PortScanResult } from './types'

// Well-known ports and their typical services, grouped by category
const PORT_MAP: Record<number, { service: string; category: PortResult['category'] }> = {
  21:    { service: 'FTP',            category: 'file' },
  22:    { service: 'SSH',            category: 'remote' },
  23:    { service: 'Telnet',         category: 'remote' },
  25:    { service: 'SMTP',           category: 'mail' },
  53:    { service: 'DNS',            category: 'dns' },
  80:    { service: 'HTTP',           category: 'web' },
  110:   { service: 'POP3',           category: 'mail' },
  111:   { service: 'RPCbind',        category: 'other' },
  135:   { service: 'MSRPC',          category: 'other' },
  139:   { service: 'NetBIOS',        category: 'file' },
  143:   { service: 'IMAP',           category: 'mail' },
  443:   { service: 'HTTPS',          category: 'web' },
  445:   { service: 'SMB',            category: 'file' },
  465:   { service: 'SMTPS',          category: 'mail' },
  587:   { service: 'SMTP/TLS',       category: 'mail' },
  993:   { service: 'IMAPS',          category: 'mail' },
  995:   { service: 'POP3S',          category: 'mail' },
  1433:  { service: 'MSSQL',          category: 'database' },
  1521:  { service: 'Oracle',         category: 'database' },
  2049:  { service: 'NFS',            category: 'file' },
  3306:  { service: 'MySQL',          category: 'database' },
  3389:  { service: 'RDP',            category: 'remote' },
  5432:  { service: 'PostgreSQL',     category: 'database' },
  5900:  { service: 'VNC',            category: 'remote' },
  5984:  { service: 'CouchDB',        category: 'database' },
  6379:  { service: 'Redis',          category: 'database' },
  6443:  { service: 'Kubernetes API', category: 'web' },
  8080:  { service: 'HTTP-Proxy',     category: 'web' },
  8443:  { service: 'HTTPS-Alt',      category: 'web' },
  8888:  { service: 'HTTP-Alt',       category: 'web' },
  9090:  { service: 'Prometheus',     category: 'web' },
  9200:  { service: 'Elasticsearch',  category: 'database' },
  9300:  { service: 'ES-Transport',   category: 'database' },
  11211: { service: 'Memcached',      category: 'database' },
  27017: { service: 'MongoDB',        category: 'database' },
  27018: { service: 'MongoDB-Shard',  category: 'database' },
}

// The default "top ports" scan list — common attack surface ports
const TOP_PORTS = Object.keys(PORT_MAP).map(Number)

// Attempt a TCP connect to a single port, with timeout
async function probePort(host: string, port: number, timeout: number): Promise<'open' | 'closed' | 'filtered'> {
  return new Promise((resolve) => {
    const socket = new net.Socket()
    let settled = false

    const finish = (result: 'open' | 'closed' | 'filtered') => {
      if (settled) return
      settled = true
      socket.destroy()
      resolve(result)
    }

    socket.setTimeout(timeout)
    socket.on('connect', () => finish('open'))
    socket.on('timeout', () => finish('filtered'))
    socket.on('error', (err: any) => {
      if (err.code === 'ECONNREFUSED') finish('closed')
      else finish('filtered')
    })
    socket.connect(port, host)
  })
}

// Grab the initial banner bytes sent by the service on a port
async function grabBanner(host: string, port: number): Promise<string | null> {
  return new Promise((resolve) => {
    const socket = new net.Socket()
    let banner = ''

    socket.setTimeout(2000)

    socket.on('data', (data) => {
      banner += data.toString('utf-8').replace(/[^\x20-\x7E]/g, '')
      socket.destroy()
    })

    socket.on('timeout', () => socket.destroy())
    socket.on('error', () => resolve(null))
    socket.on('close', () => resolve(banner.length > 0 ? banner : null))

    socket.connect(port, host, () => {
      // Some services need a nudge before they talk
      if (port === 6379) socket.write('INFO\r\n')           // Redis
      if (port === 11211) socket.write('version\r\n')       // Memcached
      if (port === 80 || port === 8080 || port === 8888) {
        socket.write(`HEAD / HTTP/1.0\r\nHost: ${host}\r\n\r\n`)
      }
    })
  })
}

export async function analyzePorts(
  host: string,
  options: { ports?: number[]; concurrency?: number; timeout?: number } = {}
): Promise<PortScanResult> {
  const { ports = TOP_PORTS, concurrency = 50, timeout = 1500 } = options
  const startTime = Date.now()

  const openPorts: PortResult[] = []
  const filteredPorts: number[] = []

  // Scan in batches to control concurrency
  for (let i = 0; i < ports.length; i += concurrency) {
    const batch = ports.slice(i, i + concurrency)
    const results = await Promise.all(
      batch.map(async (port) => {
        const state = await probePort(host, port, timeout)
        return { port, state }
      })
    )

    for (const { port, state } of results) {
      if (state === 'filtered') {
        filteredPorts.push(port)
        continue
      }
      if (state === 'closed') continue

      // Port is open — grab a banner and identify the service
      const banner = await grabBanner(host, port)
      const known = PORT_MAP[port]

      openPorts.push({
        port,
        state: 'open',
        service: known?.service ?? 'Unknown',
        category: known?.category ?? 'other',
        banner: banner ? (banner.length > 80 ? banner.substring(0, 77) + '...' : banner) : null
      })
    }
  }

  return {
    host,
    openPorts: openPorts.sort((a, b) => a.port - b.port),
    filteredPorts: filteredPorts.sort((a, b) => a - b),
    scanDuration: Date.now() - startTime
  }
}

import * as https from 'https'
import * as http from 'http'

// ─── Types ──────────────────────────────────────────────────────────────────────

export interface TechFingerprint {
  technology: string
  version: string | null
  confidence: number
  category: 'cms' | 'ci_cd' | 'monitoring' | 'database_ui' | 'api_gateway' | 'admin_panel' | 'devops' | 'cloud' | 'web_framework' | 'mail'
  knownVulns: string[]
  attackSurface: string[]
  defaultCreds: { username: string; password: string }[]
}

export interface TechSignature {
  technology: string
  category: TechFingerprint['category']
  paths: string[]
  headerMatch: Record<string, RegExp>
  bodyMatch: RegExp[]
  statusExpected: number[]
  versionPattern?: RegExp
  defaultCreds: { username: string; password: string }[]
  knownVulns: string[]
  attackSurface: string[]
}

// ─── Probe helper ───────────────────────────────────────────────────────────────

interface ProbeResult {
  status: number
  headers: Record<string, string>
  body: string
}

function probePath(baseUrl: string, path: string, timeoutMs: number): Promise<ProbeResult | null> {
  return new Promise((resolve) => {
    const url = baseUrl.replace(/\/+$/, '') + path
    const client = url.startsWith('https') ? https : http
    const req = client.get(url, { timeout: timeoutMs, rejectUnauthorized: false }, (res) => {
      const headers: Record<string, string> = {}
      for (const [key, value] of Object.entries(res.headers)) {
        headers[key.toLowerCase()] = Array.isArray(value) ? value.join(', ') : (value ?? '')
      }
      let body = ''
      res.on('data', (chunk: Buffer) => {
        if (body.length < 60000) body += chunk.toString()
      })
      res.on('end', () => resolve({ status: res.statusCode ?? 0, headers, body }))
      res.on('error', () => resolve(null))
    })
    req.on('error', () => resolve(null))
    req.on('timeout', () => { req.destroy(); resolve(null) })
  })
}

// ─── Signature database ─────────────────────────────────────────────────────────

export const TECH_SIGNATURES: TechSignature[] = [
  // ── CMS ───────────────────────────────────────────────────────────────────────
  {
    technology: 'WordPress',
    category: 'cms',
    paths: ['/wp-login.php', '/wp-admin/', '/wp-json/wp/v2/'],
    headerMatch: { 'link': /wp-json/i, 'x-powered-by': /WordPress/i },
    bodyMatch: [/wp-content/i, /wp-includes/i, /wp-login/i],
    statusExpected: [200, 301, 302, 403],
    versionPattern: /content="WordPress (\d+\.\d+\.?\d*)/i,
    defaultCreds: [{ username: 'admin', password: 'admin' }, { username: 'admin', password: 'password' }],
    knownVulns: ['CVE-2023-2982', 'CVE-2023-5561', 'CVE-2024-28890'],
    attackSurface: ['/wp-json/wp/v2/users', '/xmlrpc.php', '/wp-admin/admin-ajax.php', '/?author=1', '/wp-content/uploads/'],
  },
  {
    technology: 'Drupal',
    category: 'cms',
    paths: ['/user/login', '/core/misc/drupal.js', '/CHANGELOG.txt'],
    headerMatch: { 'x-drupal-cache': /.+/, 'x-generator': /Drupal/i },
    bodyMatch: [/Drupal\.settings/i, /drupal\.js/i, /sites\/default\/files/i],
    statusExpected: [200, 302, 403],
    versionPattern: /Drupal (\d+\.\d+\.?\d*)/i,
    defaultCreds: [{ username: 'admin', password: 'admin' }],
    knownVulns: ['CVE-2018-7600', 'CVE-2019-6340', 'CVE-2024-45440'],
    attackSurface: ['/user/login', '/admin/', '/node/1', '/CHANGELOG.txt', '/user/register'],
  },
  {
    technology: 'Joomla',
    category: 'cms',
    paths: ['/administrator/', '/administrator/manifests/files/joomla.xml'],
    headerMatch: { 'x-content-encoded-by': /Joomla/i },
    bodyMatch: [/media\/jui\//i, /com_content/i, /Joomla!/i],
    statusExpected: [200, 302, 303],
    versionPattern: /<version>(\d+\.\d+\.?\d*)<\/version>/i,
    defaultCreds: [{ username: 'admin', password: 'admin' }],
    knownVulns: ['CVE-2023-23752', 'CVE-2024-21726'],
    attackSurface: ['/administrator/', '/api/index.php/v1/config/application', '/language/en-GB/en-GB.xml'],
  },
  {
    technology: 'Ghost',
    category: 'cms',
    paths: ['/ghost/', '/ghost/api/v3/admin/', '/ghost/api/canary/admin/site/'],
    headerMatch: { 'x-powered-by': /Express/i },
    bodyMatch: [/ghost-url/i, /ghost-api/i, /Ghost\.url/i],
    statusExpected: [200, 301, 302],
    versionPattern: /"version":"(\d+\.\d+\.?\d*)"/,
    defaultCreds: [],
    knownVulns: ['CVE-2022-41654', 'CVE-2023-40028'],
    attackSurface: ['/ghost/api/v3/admin/', '/ghost/api/content/', '/ghost/'],
  },
  {
    technology: 'Magento',
    category: 'cms',
    paths: ['/admin/', '/magento_version', '/skin/frontend/'],
    headerMatch: { 'set-cookie': /MAGE_/i },
    bodyMatch: [/Mage\.Cookies/i, /magento/i, /skin\/frontend/i],
    statusExpected: [200, 302],
    versionPattern: /Magento\/(\d+\.\d+\.?\d*)/i,
    defaultCreds: [],
    knownVulns: ['CVE-2024-34102', 'CVE-2024-20720'],
    attackSurface: ['/admin/', '/downloader/', '/api/rest/', '/rest/V1/store/storeConfigs'],
  },

  // ── CI/CD ─────────────────────────────────────────────────────────────────────
  {
    technology: 'Jenkins',
    category: 'ci_cd',
    paths: ['/login', '/api/json', '/oops'],
    headerMatch: { 'x-jenkins': /.+/, 'x-jenkins-session': /.+/ },
    bodyMatch: [/Jenkins/i, /j_acegi_security_check/i, /hudson/i],
    statusExpected: [200, 302, 403],
    versionPattern: /Jenkins ver\. (\d+\.\d+\.?\d*)/i,
    defaultCreds: [{ username: 'admin', password: 'admin' }, { username: 'admin', password: 'password' }],
    knownVulns: ['CVE-2024-23897', 'CVE-2024-43044', 'CVE-2023-27898'],
    attackSurface: ['/script', '/scriptText', '/api/json', '/manage', '/env', '/asynchPeople/'],
  },
  {
    technology: 'GitLab',
    category: 'ci_cd',
    paths: ['/users/sign_in', '/api/v4/version', '/explore'],
    headerMatch: { 'x-gitlab-meta': /.+/, 'set-cookie': /_gitlab_session/i },
    bodyMatch: [/gitlab-workhorse/i, /GitLab/i, /sign_in/i],
    statusExpected: [200, 302],
    versionPattern: /"version":"(\d+\.\d+\.?\d*)"/,
    defaultCreds: [{ username: 'root', password: '5iveL!fe' }],
    knownVulns: ['CVE-2023-7028', 'CVE-2024-45409', 'CVE-2023-2825'],
    attackSurface: ['/api/v4/projects', '/api/v4/users', '/explore/projects', '/-/graphql-explorer'],
  },
  {
    technology: 'Gitea',
    category: 'ci_cd',
    paths: ['/user/login', '/api/v1/version', '/api/swagger'],
    headerMatch: {},
    bodyMatch: [/Powered by Gitea/i, /"product":"gitea"/i],
    statusExpected: [200, 302],
    versionPattern: /"version":"(\d+\.\d+\.?\d*)"/,
    defaultCreds: [],
    knownVulns: ['CVE-2023-3515', 'CVE-2024-24940'],
    attackSurface: ['/api/v1/repos/search', '/api/v1/users/search', '/api/v1/orgs', '/explore/repos'],
  },
  {
    technology: 'ArgoCD',
    category: 'ci_cd',
    paths: ['/api/v1/session', '/api/v1/applications', '/api/version'],
    headerMatch: {},
    bodyMatch: [/argocd/i, /Argo CD/i],
    statusExpected: [200, 401, 403],
    versionPattern: /"Version":"(\d+\.\d+\.?\d*)"/,
    defaultCreds: [{ username: 'admin', password: 'argocd-server-' }],
    knownVulns: ['CVE-2024-31989', 'CVE-2024-28175', 'CVE-2023-50726'],
    attackSurface: ['/api/v1/applications', '/api/v1/clusters', '/api/v1/repositories', '/api/v1/settings'],
  },
  {
    technology: 'Drone CI',
    category: 'ci_cd',
    paths: ['/login', '/api/user', '/version'],
    headerMatch: {},
    bodyMatch: [/drone/i, /"drone"/i],
    statusExpected: [200, 401],
    versionPattern: /"version":"(\d+\.\d+\.?\d*)"/,
    defaultCreds: [],
    knownVulns: ['CVE-2023-33246'],
    attackSurface: ['/api/user/repos', '/api/repos', '/api/builds'],
  },
  {
    technology: 'TeamCity',
    category: 'ci_cd',
    paths: ['/login.html', '/app/rest/server', '/app/rest/builds'],
    headerMatch: {},
    bodyMatch: [/TeamCity/i, /jetbrains/i],
    statusExpected: [200, 302, 401],
    versionPattern: /version="(\d+\.\d+\.?\d*)"/,
    defaultCreds: [],
    knownVulns: ['CVE-2024-27198', 'CVE-2024-27199', 'CVE-2023-42793'],
    attackSurface: ['/app/rest/server', '/app/rest/users', '/app/rest/projects', '/app/rest/debug/processes'],
  },

  // ── Monitoring ────────────────────────────────────────────────────────────────
  {
    technology: 'Grafana',
    category: 'monitoring',
    paths: ['/api/health', '/login', '/api/org'],
    headerMatch: { 'x-grafana-version': /.+/ },
    bodyMatch: [/grafana/i, /"database":"ok"/i],
    statusExpected: [200, 302, 401],
    versionPattern: /"version":"(\d+\.\d+\.?\d*)"/,
    defaultCreds: [{ username: 'admin', password: 'admin' }],
    knownVulns: ['CVE-2024-9264', 'CVE-2023-6152', 'CVE-2023-3128'],
    attackSurface: ['/api/dashboards/home', '/api/org', '/api/datasources', '/api/users', '/api/snapshots'],
  },
  {
    technology: 'Prometheus',
    category: 'monitoring',
    paths: ['/api/v1/status/config', '/api/v1/targets', '/graph'],
    headerMatch: {},
    bodyMatch: [/prometheus/i, /"status":"success"/i],
    statusExpected: [200],
    versionPattern: /"version":"(\d+\.\d+\.?\d*)"/,
    defaultCreds: [],
    knownVulns: ['CVE-2021-29622'],
    attackSurface: ['/api/v1/targets', '/api/v1/status/config', '/api/v1/label/__name__/values', '/api/v1/alerts'],
  },
  {
    technology: 'Kibana',
    category: 'monitoring',
    paths: ['/api/status', '/app/kibana', '/app/home'],
    headerMatch: { 'kbn-name': /.+/, 'kbn-version': /.+/ },
    bodyMatch: [/kibana/i],
    statusExpected: [200, 302, 401],
    versionPattern: /"version":{"number":"(\d+\.\d+\.?\d*)"/,
    defaultCreds: [{ username: 'elastic', password: 'changeme' }],
    knownVulns: ['CVE-2024-37287', 'CVE-2023-31414'],
    attackSurface: ['/api/status', '/api/saved_objects/_find?type=dashboard', '/api/console/proxy', '/app/dev_tools'],
  },
  {
    technology: 'Nagios',
    category: 'monitoring',
    paths: ['/nagios/', '/nagios/cgi-bin/status.cgi'],
    headerMatch: {},
    bodyMatch: [/Nagios/i, /nagios\.css/i],
    statusExpected: [200, 401],
    versionPattern: /Nagios.+?(\d+\.\d+\.?\d*)/i,
    defaultCreds: [{ username: 'nagiosadmin', password: 'nagios' }, { username: 'nagiosadmin', password: 'nagiosadmin' }],
    knownVulns: ['CVE-2023-40931', 'CVE-2023-40934'],
    attackSurface: ['/nagios/', '/nagios/cgi-bin/config.cgi', '/nagios/cgi-bin/status.cgi'],
  },
  {
    technology: 'Zabbix',
    category: 'monitoring',
    paths: ['/zabbix/', '/api_jsonrpc.php'],
    headerMatch: {},
    bodyMatch: [/Zabbix/i, /zabbix\.php/i],
    statusExpected: [200, 302],
    versionPattern: /Zabbix\s+(\d+\.\d+\.?\d*)/i,
    defaultCreds: [{ username: 'Admin', password: 'zabbix' }, { username: 'guest', password: '' }],
    knownVulns: ['CVE-2024-22120', 'CVE-2024-36466'],
    attackSurface: ['/api_jsonrpc.php', '/zabbix.php?action=dashboard.view'],
  },

  // ── Database UIs ──────────────────────────────────────────────────────────────
  {
    technology: 'phpMyAdmin',
    category: 'database_ui',
    paths: ['/phpmyadmin/', '/pma/', '/phpMyAdmin/'],
    headerMatch: { 'set-cookie': /phpMyAdmin/i },
    bodyMatch: [/phpMyAdmin/i, /pmahomme/i],
    statusExpected: [200, 302, 401],
    versionPattern: /phpMyAdmin (\d+\.\d+\.?\d*)/i,
    defaultCreds: [{ username: 'root', password: '' }, { username: 'root', password: 'root' }],
    knownVulns: ['CVE-2023-25727'],
    attackSurface: ['/phpmyadmin/', '/phpmyadmin/setup/', '/phpmyadmin/scripts/setup.php'],
  },
  {
    technology: 'Adminer',
    category: 'database_ui',
    paths: ['/adminer.php', '/adminer/'],
    headerMatch: {},
    bodyMatch: [/Adminer/i, /adminer\.css/i],
    statusExpected: [200],
    versionPattern: /Adminer (\d+\.\d+\.?\d*)/i,
    defaultCreds: [],
    knownVulns: ['CVE-2021-43008', 'CVE-2021-21311'],
    attackSurface: ['/adminer.php', '/adminer/'],
  },
  {
    technology: 'pgAdmin',
    category: 'database_ui',
    paths: ['/login', '/browser/'],
    headerMatch: {},
    bodyMatch: [/pgAdmin/i, /pgadmin/i],
    statusExpected: [200, 302],
    versionPattern: /pgAdmin (\d+)/i,
    defaultCreds: [],
    knownVulns: ['CVE-2024-3116', 'CVE-2023-5002'],
    attackSurface: ['/login', '/browser/', '/misc/ping'],
  },
  {
    technology: 'Redis Commander',
    category: 'database_ui',
    paths: ['/', '/apiv2/server/info'],
    headerMatch: {},
    bodyMatch: [/Redis Commander/i, /redis-commander/i],
    statusExpected: [200],
    defaultCreds: [],
    knownVulns: ['CVE-2021-44133'],
    attackSurface: ['/apiv2/server/info', '/apiv2/connection'],
  },
  {
    technology: 'Mongo Express',
    category: 'database_ui',
    paths: ['/', '/db/'],
    headerMatch: {},
    bodyMatch: [/Mongo Express/i, /mongo-express/i],
    statusExpected: [200, 401],
    defaultCreds: [{ username: 'admin', password: 'pass' }],
    knownVulns: ['CVE-2019-10758'],
    attackSurface: ['/', '/db/', '/checkValid'],
  },
  {
    technology: 'Elasticsearch',
    category: 'database_ui',
    paths: ['/', '/_cluster/health', '/_cat/indices'],
    headerMatch: { 'x-elastic-product': /Elasticsearch/i },
    bodyMatch: [/"cluster_name"/i, /"tagline"\s*:\s*"You Know, for Search"/i],
    statusExpected: [200, 401],
    versionPattern: /"number"\s*:\s*"(\d+\.\d+\.?\d*)"/,
    defaultCreds: [{ username: 'elastic', password: 'changeme' }],
    knownVulns: ['CVE-2023-31419', 'CVE-2023-46674'],
    attackSurface: ['/_cluster/health', '/_cat/indices', '/_search', '/_nodes', '/_mapping'],
  },

  // ── API Gateways ──────────────────────────────────────────────────────────────
  {
    technology: 'Kong Gateway',
    category: 'api_gateway',
    paths: ['/status', '/', '/kong'],
    headerMatch: { 'server': /kong/i, 'via': /kong/i },
    bodyMatch: [/"tagline"\s*:\s*"Welcome to kong"/i],
    statusExpected: [200, 404],
    versionPattern: /"version"\s*:\s*"(\d+\.\d+\.?\d*)"/,
    defaultCreds: [],
    knownVulns: ['CVE-2024-34000', 'CVE-2024-21389'],
    attackSurface: ['/status', '/', '/consumers', '/routes', '/services', '/plugins'],
  },
  {
    technology: 'Traefik',
    category: 'api_gateway',
    paths: ['/api/rawdata', '/api/version', '/dashboard/'],
    headerMatch: {},
    bodyMatch: [/traefik/i, /"routers"/i],
    statusExpected: [200, 302, 401],
    versionPattern: /"Version":"(\d+\.\d+\.?\d*)"/,
    defaultCreds: [],
    knownVulns: ['CVE-2024-45410', 'CVE-2023-47106'],
    attackSurface: ['/api/rawdata', '/api/overview', '/dashboard/', '/api/entrypoints'],
  },
  {
    technology: 'NGINX Status',
    category: 'api_gateway',
    paths: ['/nginx_status', '/status', '/stub_status'],
    headerMatch: { 'server': /nginx/i },
    bodyMatch: [/Active connections:/i, /server accepts handled requests/i],
    statusExpected: [200],
    defaultCreds: [],
    knownVulns: [],
    attackSurface: ['/nginx_status', '/.env', '/.git/config', '/server-status'],
  },
  {
    technology: 'HAProxy Stats',
    category: 'api_gateway',
    paths: ['/haproxy?stats', '/stats'],
    headerMatch: {},
    bodyMatch: [/HAProxy/i, /haproxy/i, /Statistics Report/i],
    statusExpected: [200, 401],
    versionPattern: /HAProxy version (\d+\.\d+\.?\d*)/i,
    defaultCreds: [{ username: 'admin', password: 'admin' }],
    knownVulns: ['CVE-2023-44487', 'CVE-2023-25725'],
    attackSurface: ['/haproxy?stats', '/stats;csv'],
  },

  // ── DevOps ────────────────────────────────────────────────────────────────────
  {
    technology: 'Kubernetes Dashboard',
    category: 'devops',
    paths: ['/api/v1/namespaces', '/api/v1/pods', '/api'],
    headerMatch: {},
    bodyMatch: [/"kind"\s*:\s*"(NamespaceList|PodList|APIVersions)"/i, /kubernetes/i],
    statusExpected: [200, 401, 403],
    versionPattern: /"gitVersion"\s*:\s*"v(\d+\.\d+\.?\d*)"/,
    defaultCreds: [],
    knownVulns: ['CVE-2024-9042', 'CVE-2023-5528', 'CVE-2023-3676'],
    attackSurface: ['/api/v1/namespaces', '/api/v1/pods', '/api/v1/secrets', '/apis', '/version', '/healthz'],
  },
  {
    technology: 'Docker Registry',
    category: 'devops',
    paths: ['/v2/', '/v2/_catalog'],
    headerMatch: { 'docker-distribution-api-version': /.+/ },
    bodyMatch: [/"repositories"/i],
    statusExpected: [200, 401],
    defaultCreds: [],
    knownVulns: ['CVE-2023-2253'],
    attackSurface: ['/v2/_catalog', '/v2/'],
  },
  {
    technology: 'Portainer',
    category: 'devops',
    paths: ['/api/status', '/api/system/version', '/#!/init/admin'],
    headerMatch: {},
    bodyMatch: [/portainer/i, /"Version"/i],
    statusExpected: [200, 302],
    versionPattern: /"Version"\s*:\s*"(\d+\.\d+\.?\d*)"/,
    defaultCreds: [],
    knownVulns: ['CVE-2024-33661'],
    attackSurface: ['/api/status', '/api/endpoints', '/api/stacks', '/api/users'],
  },
  {
    technology: 'Consul',
    category: 'devops',
    paths: ['/v1/agent/self', '/v1/catalog/services', '/ui/'],
    headerMatch: { 'x-consul-knownleader': /.+/ },
    bodyMatch: [/consul/i, /"Config"/i],
    statusExpected: [200],
    versionPattern: /"Version"\s*:\s*"(\d+\.\d+\.?\d*)"/,
    defaultCreds: [],
    knownVulns: ['CVE-2024-10086', 'CVE-2023-1297'],
    attackSurface: ['/v1/agent/self', '/v1/catalog/services', '/v1/kv/', '/v1/agent/members', '/ui/'],
  },
  {
    technology: 'Vault',
    category: 'devops',
    paths: ['/v1/sys/health', '/v1/sys/seal-status', '/ui/'],
    headerMatch: {},
    bodyMatch: [/"sealed"/i, /"cluster_name"/i, /vault/i],
    statusExpected: [200, 429, 472, 473, 501, 503],
    versionPattern: /"version"\s*:\s*"(\d+\.\d+\.?\d*)"/,
    defaultCreds: [],
    knownVulns: ['CVE-2024-2660', 'CVE-2023-5954'],
    attackSurface: ['/v1/sys/health', '/v1/sys/seal-status', '/v1/sys/mounts', '/v1/secret/data/'],
  },
  {
    technology: 'Ansible AWX',
    category: 'devops',
    paths: ['/api/v2/', '/api/v2/ping/'],
    headerMatch: {},
    bodyMatch: [/awx/i, /"ha"\s*:/i, /"active_node"/i],
    statusExpected: [200, 301, 401],
    versionPattern: /"version"\s*:\s*"(\d+\.\d+\.?\d*)"/,
    defaultCreds: [{ username: 'admin', password: 'password' }],
    knownVulns: ['CVE-2024-6840'],
    attackSurface: ['/api/v2/ping/', '/api/v2/me/', '/api/v2/inventories/', '/api/v2/job_templates/'],
  },

  // ── Cloud ─────────────────────────────────────────────────────────────────────
  {
    technology: 'MinIO',
    category: 'cloud',
    paths: ['/minio/health/live', '/minio/health/ready', '/login'],
    headerMatch: { 'server': /MinIO/i },
    bodyMatch: [/minio/i, /MinIO Console/i],
    statusExpected: [200, 403],
    versionPattern: /RELEASE\.(\d{4}-\d{2}-\d{2})/,
    defaultCreds: [{ username: 'minioadmin', password: 'minioadmin' }],
    knownVulns: ['CVE-2024-24747', 'CVE-2023-28434'],
    attackSurface: ['/minio/health/live', '/minio/health/cluster', '/login'],
  },
  {
    technology: 'AWS Metadata',
    category: 'cloud',
    paths: ['/latest/meta-data/', '/latest/dynamic/instance-identity/document'],
    headerMatch: {},
    bodyMatch: [/ami-id/i, /instance-id/i, /accountId/i],
    statusExpected: [200],
    defaultCreds: [],
    knownVulns: ['SSRF-to-IMDS'],
    attackSurface: ['/latest/meta-data/iam/security-credentials/', '/latest/user-data'],
  },
  {
    technology: 'CloudFront',
    category: 'cloud',
    paths: ['/'],
    headerMatch: { 'x-amz-cf-id': /.+/, 'x-amz-cf-pop': /.+/, 'server': /CloudFront/i },
    bodyMatch: [],
    statusExpected: [200, 301, 302, 403],
    defaultCreds: [],
    knownVulns: [],
    attackSurface: [],
  },
  {
    technology: 'Google Cloud Storage',
    category: 'cloud',
    paths: ['/'],
    headerMatch: { 'x-goog-generation': /.+/, 'x-guploader-uploadid': /.+/ },
    bodyMatch: [/storage\.googleapis\.com/i],
    statusExpected: [200, 403],
    defaultCreds: [],
    knownVulns: [],
    attackSurface: [],
  },

  // ── Admin Panels ──────────────────────────────────────────────────────────────
  {
    technology: 'cPanel',
    category: 'admin_panel',
    paths: ['/cpanel', '/:2083/', '/login/?login_only=1'],
    headerMatch: { 'server': /cpsrvd/i },
    bodyMatch: [/cPanel/i, /cpanel/i, /cpsrvd/i],
    statusExpected: [200, 301, 302],
    versionPattern: /cPanel.*?(\d+\.\d+)/i,
    defaultCreds: [],
    knownVulns: ['CVE-2024-29886', 'CVE-2023-29489'],
    attackSurface: ['/cpanel', '/webmail', '/whm'],
  },
  {
    technology: 'Webmin',
    category: 'admin_panel',
    paths: ['/', '/session_login.cgi'],
    headerMatch: { 'server': /MiniServ/i },
    bodyMatch: [/Webmin/i, /webmin/i],
    statusExpected: [200, 302],
    versionPattern: /Webmin (\d+\.\d+\.?\d*)/i,
    defaultCreds: [{ username: 'root', password: 'root' }, { username: 'admin', password: 'admin' }],
    knownVulns: ['CVE-2024-12828', 'CVE-2023-38303'],
    attackSurface: ['/session_login.cgi', '/sysinfo.cgi', '/package-updates/'],
  },
  {
    technology: 'Plesk',
    category: 'admin_panel',
    paths: ['/login', '/login_up.php'],
    headerMatch: {},
    bodyMatch: [/Plesk/i, /plesk/i],
    statusExpected: [200, 302],
    versionPattern: /Plesk.*?(\d+\.\d+\.?\d*)/i,
    defaultCreds: [],
    knownVulns: ['CVE-2023-45360'],
    attackSurface: ['/login', '/modules/'],
  },

  // ── Web Frameworks ────────────────────────────────────────────────────────────
  {
    technology: 'Spring Boot Actuator',
    category: 'web_framework',
    paths: ['/actuator', '/actuator/health', '/actuator/env'],
    headerMatch: {},
    bodyMatch: [/"status"\s*:\s*"UP"/i, /"_links"/i, /actuator/i],
    statusExpected: [200],
    defaultCreds: [],
    knownVulns: ['CVE-2024-38816', 'CVE-2022-22965'],
    attackSurface: ['/actuator/env', '/actuator/heapdump', '/actuator/mappings', '/actuator/configprops', '/actuator/beans'],
  },
  {
    technology: 'Laravel Telescope',
    category: 'web_framework',
    paths: ['/telescope', '/telescope/requests'],
    headerMatch: {},
    bodyMatch: [/telescope/i, /Laravel Telescope/i],
    statusExpected: [200, 302],
    defaultCreds: [],
    knownVulns: [],
    attackSurface: ['/telescope/requests', '/telescope/exceptions', '/telescope/queries', '/telescope/logs'],
  },
  {
    technology: 'Swagger UI',
    category: 'web_framework',
    paths: ['/swagger-ui.html', '/swagger-ui/', '/api-docs', '/swagger.json'],
    headerMatch: {},
    bodyMatch: [/SwaggerUIBundle/i, /swagger-ui/i, /"openapi"/i, /"swagger"/i],
    statusExpected: [200, 301],
    defaultCreds: [],
    knownVulns: [],
    attackSurface: ['/swagger-ui.html', '/swagger.json', '/v2/api-docs', '/v3/api-docs', '/openapi.json'],
  },

  // ── Mail ──────────────────────────────────────────────────────────────────────
  {
    technology: 'Roundcube',
    category: 'mail',
    paths: ['/', '/?_task=login'],
    headerMatch: {},
    bodyMatch: [/roundcube/i, /rcmloginuser/i],
    statusExpected: [200],
    versionPattern: /roundcube.*?(\d+\.\d+\.?\d*)/i,
    defaultCreds: [],
    knownVulns: ['CVE-2024-37383', 'CVE-2023-43770'],
    attackSurface: ['/?_task=login', '/installer/'],
  },
  {
    technology: 'Zimbra',
    category: 'mail',
    paths: ['/', '/zimbraAdmin/', '/mail/'],
    headerMatch: { 'set-cookie': /ZM_AUTH_TOKEN/i },
    bodyMatch: [/zimbra/i, /ZmSkin/i],
    statusExpected: [200, 302],
    versionPattern: /Zimbra (\d+\.\d+\.?\d*)/i,
    defaultCreds: [],
    knownVulns: ['CVE-2024-45519', 'CVE-2023-37580'],
    attackSurface: ['/zimbraAdmin/', '/service/soap/', '/mail/'],
  },
]

// ─── Core fingerprinting logic ──────────────────────────────────────────────────

async function matchSignature(baseUrl: string, sig: TechSignature, timeoutMs: number): Promise<TechFingerprint | null> {
  let bestConfidence = 0
  let detectedVersion: string | null = null
  let pathHits = 0
  let headerHits = 0
  let bodyHits = 0

  for (const path of sig.paths) {
    const result = await probePath(baseUrl, path, timeoutMs)
    if (!result) continue

    const statusOk = sig.statusExpected.length === 0 || sig.statusExpected.includes(result.status)
    if (!statusOk) continue

    pathHits++

    // Check headers
    for (const [headerName, pattern] of Object.entries(sig.headerMatch)) {
      const val = result.headers[headerName]
      if (val && pattern.test(val)) {
        headerHits++
      }
    }

    // Check body
    for (const pattern of sig.bodyMatch) {
      if (pattern.test(result.body)) {
        bodyHits++
      }
    }

    // Try version extraction
    if (!detectedVersion && sig.versionPattern) {
      // Check body first, then headers
      const bodyVerMatch = result.body.match(sig.versionPattern)
      if (bodyVerMatch && bodyVerMatch[1]) {
        detectedVersion = bodyVerMatch[1]
      } else {
        for (const val of Object.values(result.headers)) {
          const headerVerMatch = val.match(sig.versionPattern)
          if (headerVerMatch && headerVerMatch[1]) {
            detectedVersion = headerVerMatch[1]
            break
          }
        }
      }
    }
  }

  // Scoring: path hit = 20 per path (max 40), header hit = 20 each (max 30), body hit = 15 each (max 30), version = +10
  if (pathHits === 0 && headerHits === 0 && bodyHits === 0) return null

  bestConfidence += Math.min(pathHits * 20, 40)
  bestConfidence += Math.min(headerHits * 20, 30)
  bestConfidence += Math.min(bodyHits * 15, 30)
  if (detectedVersion) bestConfidence += 10

  bestConfidence = Math.min(bestConfidence, 100)

  // Require minimum confidence to avoid false positives
  if (bestConfidence < 25) return null

  return {
    technology: sig.technology,
    version: detectedVersion,
    confidence: bestConfidence,
    category: sig.category,
    knownVulns: sig.knownVulns,
    attackSurface: sig.attackSurface,
    defaultCreds: sig.defaultCreds,
  }
}

// ─── Public API ─────────────────────────────────────────────────────────────────

/**
 * Fingerprint a single subdomain URL by probing all known tech signatures.
 * Returns matching technologies sorted by confidence (highest first).
 */
export async function fingerprintSubdomain(url: string, timeoutMs = 3000): Promise<TechFingerprint[]> {
  const results: TechFingerprint[] = []

  // Run all signature checks in parallel for speed
  const promises = TECH_SIGNATURES.map((sig) => matchSignature(url, sig, timeoutMs))
  const matches = await Promise.all(promises)

  for (const match of matches) {
    if (match) results.push(match)
  }

  return results.sort((a, b) => b.confidence - a.confidence)
}

/**
 * Batch fingerprint alive subdomains with controlled concurrency.
 * Returns a map of subdomain URL → detected technologies.
 */
export async function fingerprintSubdomains(
  subdomains: { subdomain: string; isAlive: boolean }[],
  concurrency = 10
): Promise<Map<string, TechFingerprint[]>> {
  const alive = subdomains.filter((s) => s.isAlive)
  const resultMap = new Map<string, TechFingerprint[]>()

  // Process in batches to respect concurrency
  for (let i = 0; i < alive.length; i += concurrency) {
    const batch = alive.slice(i, i + concurrency)
    const batchPromises = batch.map(async (entry) => {
      // Try HTTPS first, fall back to HTTP
      const httpsUrl = `https://${entry.subdomain}`
      const httpUrl = `http://${entry.subdomain}`

      let fingerprints = await fingerprintSubdomain(httpsUrl)
      if (fingerprints.length === 0) {
        fingerprints = await fingerprintSubdomain(httpUrl)
      }
      return { subdomain: entry.subdomain, fingerprints }
    })

    const batchResults = await Promise.all(batchPromises)
    for (const { subdomain, fingerprints } of batchResults) {
      if (fingerprints.length > 0) {
        resultMap.set(subdomain, fingerprints)
      }
    }
  }

  return resultMap
}

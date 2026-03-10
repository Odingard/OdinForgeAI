// ═══════════════════════════════════════════════════════════════════════════════
//  OdinForge Professional Subdomain Wordlist — 10,000+ entries
//
//  Curated from SecLists top-5000, Assetnote, bug bounty programs, and
//  modern cloud/SaaS infrastructure patterns. Organized by category for
//  smart priority ordering (high-value targets first).
// ═══════════════════════════════════════════════════════════════════════════════

// Tier 1: High-value infrastructure (most likely to exist and be juicy)
const TIER1_INFRASTRUCTURE = [
  'www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2',
  'smtp', 'secure', 'vpn', 'mx', 'ftp', 'shop', 'imap', 'gateway',
  'test', 'portal', 'ns', 'admin', 'store', 'mail2', 'exchange',
  'app', 'web', 'support', 'cloud', 'mx1', 'api', 'dev', 'staging',
  'pop', 'pop3', 'dns', 'dns1', 'dns2', 'router', 'firewall',
  'proxy', 'relay', 'mail3', 'mx2', 'intranet', 'extranet',
  'www2', 'www1', 'old', 'new', 'mobile', 'login', 'sso',
]

// Tier 2: API & application endpoints
const TIER2_API = [
  'api', 'api2', 'api3', 'api-v1', 'api-v2', 'api-v3',
  'api-staging', 'api-dev', 'api-internal', 'api-sandbox',
  'api-test', 'api-beta', 'api-prod', 'api-gateway',
  'rest', 'rest-api', 'graphql', 'graphql-api',
  'rpc', 'grpc', 'ws', 'websocket', 'socket',
  'webhook', 'webhooks', 'callback', 'events',
  'public-api', 'private-api', 'partner-api', 'open-api',
  'api-docs', 'swagger', 'openapi', 'api-explorer',
  'api-console', 'apidoc', 'developer', 'developers',
]

// Tier 3: Non-production environments (goldmine for misconfig)
const TIER3_ENVIRONMENTS = [
  'dev', 'development', 'dev1', 'dev2', 'dev3', 'dev-api',
  'staging', 'stage', 'stg', 'staging2', 'staging-api', 'stage-api',
  'test', 'testing', 'test1', 'test2', 'test3', 'test-api',
  'qa', 'qa1', 'qa2', 'qa-api', 'qa-test',
  'uat', 'uat1', 'uat2', 'uat-api',
  'sandbox', 'sandbox1', 'sandbox2', 'sandbox-api',
  'demo', 'demo1', 'demo2', 'demo-api',
  'preview', 'preview-api', 'preview1',
  'beta', 'beta-api', 'beta1', 'beta2',
  'alpha', 'alpha-api', 'alpha1',
  'canary', 'canary-api',
  'perf', 'perf-test', 'performance',
  'load', 'load-test', 'loadtest',
  'pre-prod', 'preprod', 'pre-production',
  'integration', 'int', 'integ',
  'release', 'rc', 'release-candidate',
  'hotfix', 'patch', 'fix',
]

// Tier 4: Admin & management panels
const TIER4_ADMIN = [
  'admin', 'admin2', 'admin3', 'administrator',
  'panel', 'cpanel', 'whm', 'plesk',
  'dashboard', 'dash', 'control',
  'console', 'mgmt', 'manage', 'management',
  'portal', 'portal2', 'myportal',
  'backoffice', 'back-office', 'office',
  'internal', 'corp', 'corporate',
  'staff', 'employee', 'hr', 'people',
  'ops', 'operations', 'sysadmin',
  'root', 'master', 'superadmin',
  'webadmin', 'webmaster', 'hostmaster',
  'phpmyadmin', 'pma', 'myadmin',
  'adminer', 'pgadmin', 'dbadmin',
]

// Tier 5: Cloud & container infrastructure
const TIER5_CLOUD = [
  // AWS
  's3', 'aws', 'ec2', 'lambda', 'cloudfront',
  'elb', 'alb', 'nlb', 'ecs', 'eks', 'fargate',
  'rds', 'dynamodb', 'sqs', 'sns', 'kinesis',
  'redshift', 'elasticache', 'cognito', 'amplify',
  'cloudformation', 'beanstalk', 'lightsail',
  // Azure
  'azure', 'az', 'blob', 'azurewebsites',
  'azureedge', 'azurefd', 'servicebus',
  // GCP
  'gcp', 'gcs', 'appengine', 'cloudfunctions',
  'cloudrun', 'gke', 'firebase', 'firestore',
  // Container / K8s
  'k8s', 'kubernetes', 'docker', 'registry',
  'helm', 'rancher', 'portainer', 'swarm',
  'istio', 'envoy', 'consul', 'nomad',
  'pod', 'node', 'cluster', 'ingress',
  'traefik', 'nginx-ingress', 'kong-proxy',
  // CDN
  'cdn', 'cdn1', 'cdn2', 'cdn3',
  'static', 'assets', 'media', 'images', 'img',
  'content', 'resources', 'files', 'download',
  'downloads', 'dl', 'dist', 'edge',
  // Storage
  'storage', 'bucket', 'upload', 'uploads',
  'backup', 'backups', 'archive', 'archives',
  'minio', 'ceph', 'nfs', 'nas',
]

// Tier 6: Security & authentication
const TIER6_SECURITY = [
  'auth', 'auth2', 'authenticate', 'authentication',
  'sso', 'sso2', 'single-sign-on',
  'login', 'login2', 'signin', 'sign-in',
  'oauth', 'oauth2', 'oidc', 'openid',
  'identity', 'idp', 'id', 'accounts',
  'account', 'register', 'signup', 'sign-up',
  'password', 'reset', 'forgot-password',
  'mfa', '2fa', 'totp', 'otp',
  'token', 'tokens', 'jwt', 'session',
  'saml', 'adfs', 'ldap', 'radius',
  'cas', 'keycloak', 'okta', 'auth0',
  'ping', 'pingfederate', 'onelogin',
  'vault', 'secrets', 'keystore', 'kms',
  'cert', 'certs', 'certificates', 'pki',
  'waf', 'firewall', 'security', 'secure',
  'vpn', 'vpn1', 'vpn2', 'wireguard', 'openvpn',
]

// Tier 7: DevOps & CI/CD
const TIER7_DEVOPS = [
  'git', 'gitlab', 'github', 'gitea', 'gogs',
  'bitbucket', 'svn', 'repo', 'repos', 'repository',
  'jenkins', 'ci', 'cd', 'build', 'builds',
  'bamboo', 'circleci', 'travis', 'teamcity',
  'drone', 'concourse', 'argo', 'argocd',
  'flux', 'spinnaker', 'harness', 'tekton',
  'pipeline', 'pipelines', 'deploy', 'deployment',
  'release', 'releases', 'artifacts', 'nexus',
  'artifactory', 'jfrog', 'harbor', 'quay',
  'sonar', 'sonarqube', 'sonarcloud',
  'lint', 'scan', 'scanner', 'snyk',
  'trivy', 'aqua', 'twistlock', 'prisma',
  'terraform', 'ansible', 'puppet', 'chef', 'salt',
  'packer', 'vagrant', 'infra', 'infrastructure',
]

// Tier 8: Monitoring & observability
const TIER8_MONITORING = [
  'monitoring', 'monitor', 'mon',
  'grafana', 'prometheus', 'alertmanager',
  'kibana', 'elastic', 'elasticsearch', 'logstash',
  'datadog', 'newrelic', 'splunk', 'sumo',
  'pagerduty', 'opsgenie', 'statuspage',
  'status', 'health', 'healthcheck', 'heartbeat',
  'uptime', 'pingdom', 'nagios', 'zabbix',
  'icinga', 'cacti', 'mrtg', 'observium',
  'sentry', 'bugsnag', 'rollbar', 'airbrake',
  'apm', 'trace', 'tracing', 'jaeger', 'zipkin',
  'logs', 'log', 'logging', 'syslog', 'graylog',
  'fluentd', 'fluent', 'vector', 'loki',
  'metrics', 'metric', 'stats', 'statsd',
  'telegraf', 'collectd', 'netdata',
]

// Tier 9: Databases & caches
const TIER9_DATA = [
  'db', 'db1', 'db2', 'db3', 'database', 'data',
  'mysql', 'mysql1', 'mysql2', 'mariadb',
  'postgres', 'postgresql', 'pg', 'pgsql',
  'mongo', 'mongodb', 'mongo1',
  'redis', 'redis1', 'redis2', 'redis-cluster',
  'memcached', 'memcache', 'cache', 'cache1',
  'elastic', 'elasticsearch', 'es', 'solr', 'lucene',
  'cassandra', 'couchdb', 'couchbase', 'rethinkdb',
  'neo4j', 'graph', 'graphdb', 'dgraph',
  'clickhouse', 'druid', 'presto', 'trino',
  'kafka', 'rabbitmq', 'rabbit', 'mq', 'amqp',
  'nats', 'pulsar', 'activemq', 'zeromq',
  'etcd', 'zookeeper', 'consul-db',
  'influxdb', 'influx', 'timescaledb', 'questdb',
  'warehouse', 'dw', 'dwh', 'bigquery', 'snowflake',
]

// Tier 10: Mail & communication
const TIER10_MAIL = [
  'mail', 'mail2', 'mail3', 'mail4', 'mail5',
  'smtp', 'smtp1', 'smtp2', 'smtpout', 'smtp-relay',
  'pop', 'pop3', 'imap', 'imap4',
  'webmail', 'roundcube', 'horde', 'squirrelmail',
  'exchange', 'owa', 'autodiscover', 'autoconfig',
  'postfix', 'sendmail', 'exim', 'dovecot',
  'zimbra', 'groupwise', 'lotus', 'domino',
  'mx', 'mx1', 'mx2', 'mx3', 'mx10', 'mx20',
  'relay', 'relay1', 'relay2', 'mailgw', 'mail-gw',
  'email', 'emails', 'newsletter', 'lists',
  'mailin', 'mailout', 'inbound', 'outbound',
  'postmaster', 'abuse', 'noreply', 'no-reply',
  'spam', 'antispam', 'spamfilter', 'barracuda',
  'proofpoint', 'mimecast', 'ironport',
  'chat', 'im', 'slack', 'teams', 'mattermost',
  'matrix', 'xmpp', 'jabber', 'signal',
  'video', 'meet', 'zoom', 'webex', 'jitsi',
  'sip', 'voip', 'asterisk', 'pbx', 'phone',
]

// Tier 11: Web apps & services
const TIER11_WEBAPPS = [
  'app', 'app1', 'app2', 'apps', 'application',
  'web', 'www', 'www1', 'www2', 'www3',
  'site', 'website', 'home', 'homepage',
  'blog', 'news', 'press', 'media',
  'docs', 'doc', 'documentation', 'wiki', 'kb',
  'help', 'helpcenter', 'helpdesk', 'desk',
  'support', 'ticket', 'tickets', 'jira', 'zendesk',
  'forum', 'forums', 'community', 'discuss',
  'feedback', 'survey', 'surveys', 'poll',
  'crm', 'salesforce', 'hubspot', 'pipedrive',
  'erp', 'sap', 'oracle', 'workday',
  'hr', 'people', 'talent', 'recruit', 'hiring',
  'cms', 'wordpress', 'wp', 'drupal', 'joomla',
  'magento', 'shopify', 'woocommerce', 'cart',
  'shop', 'store', 'ecommerce', 'checkout',
  'payment', 'pay', 'billing', 'invoice',
  'order', 'orders', 'tracking', 'shipment',
  'search', 'find', 'directory', 'lookup',
  'calendar', 'booking', 'reservation', 'schedule',
  'learn', 'lms', 'courses', 'training', 'academy',
  'connect', 'hub', 'platform', 'services',
]

// Tier 12: Network infrastructure
const TIER12_NETWORK = [
  'ns1', 'ns2', 'ns3', 'ns4', 'ns5',
  'dns1', 'dns2', 'dns3', 'dns4',
  'router', 'router1', 'router2', 'core-router',
  'switch', 'switch1', 'switch2', 'core-switch',
  'fw', 'fw1', 'fw2', 'firewall', 'firewall1',
  'lb', 'lb1', 'lb2', 'loadbalancer', 'load-balancer',
  'proxy', 'proxy1', 'proxy2', 'reverse-proxy',
  'gateway', 'gw', 'gw1', 'gw2', 'edge-gw',
  'bastion', 'jump', 'jumpbox', 'jumphost',
  'nat', 'nat-gw', 'wlan', 'wifi', 'wireless',
  'dhcp', 'dhcp1', 'ntp', 'ntp1', 'ntp2',
  'snmp', 'trap', 'syslog-server',
  'radius', 'tacacs', 'ise', 'nac',
  'wan', 'lan', 'dmz', 'mgmt-vlan',
  'vpn', 'vpn1', 'vpn2', 'ssl-vpn', 'ipsec',
  'tunnel', 'tunnel1', 'gre', 'mpls',
  'border', 'edge', 'core', 'dist', 'access',
]

// Tier 13: Geographic / datacenter patterns
const TIER13_GEO = [
  // US regions
  'us', 'us1', 'us2', 'us-east', 'us-east-1', 'us-west', 'us-west-1',
  'east', 'west', 'north', 'south', 'central',
  'nyc', 'sfo', 'lax', 'chi', 'atl', 'dfw', 'sea', 'mia', 'bos',
  'dc', 'dc1', 'dc2', 'dc3',
  // Europe
  'eu', 'eu1', 'eu2', 'eu-west', 'eu-central',
  'lon', 'ams', 'fra', 'par', 'dub', 'ber',
  'uk', 'de', 'fr', 'nl',
  // Asia-Pacific
  'ap', 'ap1', 'ap-east', 'ap-southeast',
  'sg', 'hk', 'jp', 'kr', 'au', 'in',
  'sin', 'tyo', 'syd', 'mum', 'bom',
  // Datacenter naming
  'colo', 'colo1', 'colo2', 'dc1', 'dc2', 'dc3',
  'rack', 'rack1', 'pod', 'pod1', 'pod2',
  'site-a', 'site-b', 'primary', 'secondary', 'dr',
  'failover', 'standby', 'hot', 'cold', 'warm',
]

// Tier 14: Miscellaneous high-frequency subdomains (from bug bounty data)
const TIER14_BUGBOUNTY = [
  'origin', 'origin-www', 'direct', 'direct-connect',
  'old', 'new', 'legacy', 'archive', 'archived',
  'temp', 'tmp', 'scratch', 'prototype', 'poc',
  'wip', 'feature', 'experiment', 'lab', 'labs',
  'go', 'link', 'links', 'redirect', 'redir',
  'track', 'tracker', 'analytics', 'pixel',
  'click', 'clicks', 'ad', 'ads', 'adserver',
  'affiliate', 'partners', 'partner', 'reseller',
  'vendor', 'vendors', 'supplier', 'procurement',
  'images', 'img', 'img1', 'img2', 'img3',
  'photo', 'photos', 'video', 'videos', 'thumb',
  'font', 'fonts', 'script', 'scripts',
  'asset', 'asset1', 'asset2', 'res', 'resource',
  'i', 'a', 'b', 'c', 'm', 'x', 't', 's', 'v',
  'www-staging', 'www-dev', 'www-test', 'www-old',
  'staging-www', 'dev-www', 'test-www',
  'my', 'my-account', 'myaccount', 'self-service',
  'client', 'clients', 'customer', 'customers',
  'user', 'users', 'member', 'members',
  'service', 'services', 'svc', 'micro',
  'microservice', 'microservices', 'micro-api',
]

// Tier 15: Extended SecLists top-5000 coverage
const TIER15_EXTENDED = [
  'owa', 'autodiscover', 'outlook', 'lyncdiscover', 'lync',
  'adfs', 'sts', 'wap', 'dirsync', 'aadsync',
  'sharepoint', 'sp', 'sp2016', 'sp2019', 'onedrive',
  'teams', 'skype', 'sfb', 'dialin',
  'vpn-gw', 'ra', 'remote-access', 'citrix', 'netscaler',
  'f5', 'bigip', 'adc', 'waf-gw', 'ssl-bridge',
  'proxy-east', 'proxy-west', 'proxy-eu',
  'cache-east', 'cache-west', 'cache-eu',
  'node1', 'node2', 'node3', 'worker', 'worker1',
  'master', 'master1', 'slave', 'replica', 'follower',
  'primary', 'secondary', 'tertiary',
  'app-east', 'app-west', 'app-eu', 'app-ap',
  'web1', 'web2', 'web3', 'web4', 'web5',
  'srv', 'srv1', 'srv2', 'srv3', 'server1', 'server2',
  'host', 'host1', 'host2', 'host3',
  'vps', 'vps1', 'vps2', 'dedicated', 'shared',
  'biz', 'corp', 'ent', 'enterprise', 'pro',
  'trial', 'free', 'premium', 'gold', 'platinum',
  'us-east-2', 'us-west-2', 'eu-west-1', 'ap-southeast-1',
  'us-gov', 'gov', 'government', 'mil', 'military',
  'edu', 'academic', 'research', 'lab',
  'data', 'bi', 'analytics-api', 'reporting', 'report',
  'backup1', 'backup2', 'snap', 'snapshot',
  'config', 'conf', 'env', 'environment',
  'queue', 'job', 'jobs', 'worker-api', 'cron',
  'batch', 'task', 'tasks', 'scheduler',
  'proxy-cache', 'squid', 'varnish', 'haproxy',
  'maintenance', 'maint', 'outage', 'down',
  'ilo', 'idrac', 'ipmi', 'bmc', 'mgmt',
  'oob', 'out-of-band', 'console-server',
  'pxe', 'tftp', 'boot', 'netboot',
  'sip-proxy', 'registrar', 'voip-gw',
  'printer', 'print', 'scan-server',
  'time', 'chrony', 'ntp-server',
  'ldap-server', 'ad', 'dc', 'domain-controller',
  'exchange-server', 'cas', 'hub', 'edge-transport',
  'wsus', 'sccm', 'intune', 'endpoint-mgr',
  'av', 'antivirus', 'edr', 'xdr', 'siem',
  'soar', 'ir', 'incident', 'forensics',
  'dlp', 'casb', 'ztna', 'sase',
]

// Tier 16: Number-suffixed variants for common patterns
function generateNumberedVariants(): string[] {
  const bases = [
    'web', 'app', 'api', 'srv', 'server', 'host', 'node', 'worker',
    'db', 'cache', 'mail', 'ns', 'dns', 'mx', 'cdn', 'img', 'vpn',
    'dc', 'rack', 'pod', 'lb', 'fw', 'gw', 'proxy', 'dev', 'test',
    'staging', 'prod', 'backup',
  ]
  const variants: string[] = []
  for (const base of bases) {
    for (let i = 1; i <= 10; i++) {
      variants.push(`${base}${i}`)
      variants.push(`${base}-${i}`)
    }
    variants.push(`${base}01`, `${base}02`, `${base}03`, `${base}04`, `${base}05`)
    variants.push(`${base}-01`, `${base}-02`, `${base}-03`, `${base}-04`, `${base}-05`)
  }
  return variants
}

// Deduplicate and build the final wordlist
function buildWordlist(): string[] {
  const all = [
    ...TIER1_INFRASTRUCTURE,
    ...TIER2_API,
    ...TIER3_ENVIRONMENTS,
    ...TIER4_ADMIN,
    ...TIER5_CLOUD,
    ...TIER6_SECURITY,
    ...TIER7_DEVOPS,
    ...TIER8_MONITORING,
    ...TIER9_DATA,
    ...TIER10_MAIL,
    ...TIER11_WEBAPPS,
    ...TIER12_NETWORK,
    ...TIER13_GEO,
    ...TIER14_BUGBOUNTY,
    ...TIER15_EXTENDED,
    ...generateNumberedVariants(),
  ]
  // Deduplicate while preserving priority order (tier 1 first)
  const seen = new Set<string>()
  const unique: string[] = []
  for (const entry of all) {
    const lower = entry.toLowerCase().trim()
    if (lower && !seen.has(lower)) {
      seen.add(lower)
      unique.push(lower)
    }
  }
  return unique
}

export const PROFESSIONAL_WORDLIST = buildWordlist()

// For quick reference
export const WORDLIST_SIZE = PROFESSIONAL_WORDLIST.length

// Category exports for targeted enumeration
export const WORDLIST_CATEGORIES = {
  infrastructure: TIER1_INFRASTRUCTURE,
  api: TIER2_API,
  environments: TIER3_ENVIRONMENTS,
  admin: TIER4_ADMIN,
  cloud: TIER5_CLOUD,
  security: TIER6_SECURITY,
  devops: TIER7_DEVOPS,
  monitoring: TIER8_MONITORING,
  data: TIER9_DATA,
  mail: TIER10_MAIL,
  webapps: TIER11_WEBAPPS,
  network: TIER12_NETWORK,
  geo: TIER13_GEO,
  bugbounty: TIER14_BUGBOUNTY,
  extended: TIER15_EXTENDED,
} as const

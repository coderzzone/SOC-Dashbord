# API Integration Guide

This guide provides detailed instructions for integrating the SOC Dashboard with various security tools and platforms.

## 🔌 SIEM Integration APIs

### Splunk REST API Integration

#### Authentication Methods

**1. Basic Authentication**
```typescript
const splunkAuth = {
  username: 'your-username',
  password: 'your-password',
  baseURL: 'https://your-splunk-server:8089'
};

// Create session
const createSession = async () => {
  const response = await fetch(`${splunkAuth.baseURL}/services/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      username: splunkAuth.username,
      password: splunkAuth.password
    })
  });
  
  const sessionKey = await response.text();
  return sessionKey.match(/<sessionKey>(.*?)<\/sessionKey>/)[1];
};
```

**2. Token Authentication**
```typescript
const splunkToken = {
  token: 'your-splunk-token',
  baseURL: 'https://your-splunk-server:8089'
};

const headers = {
  'Authorization': `Splunk ${splunkToken.token}`,
  'Content-Type': 'application/json'
};
```

#### Search API Usage

**Real-time Search**
```typescript
const realtimeSearch = async (query: string) => {
  // Create search job
  const searchResponse = await fetch(`${baseURL}/services/search/jobs`, {
    method: 'POST',
    headers,
    body: new URLSearchParams({
      search: query,
      exec_mode: 'normal',
      earliest_time: 'rt-1m',
      latest_time: 'rt'
    })
  });
  
  const searchId = await searchResponse.text();
  const sid = searchId.match(/<sid>(.*?)<\/sid>/)[1];
  
  // Poll for results
  const pollResults = async () => {
    const resultsResponse = await fetch(
      `${baseURL}/services/search/jobs/${sid}/results?output_mode=json`,
      { headers }
    );
    return await resultsResponse.json();
  };
  
  return pollResults();
};
```

**Historical Search**
```typescript
const historicalSearch = async (query: string, timeRange: { start: string, end: string }) => {
  const searchParams = new URLSearchParams({
    search: query,
    earliest_time: timeRange.start,
    latest_time: timeRange.end,
    output_mode: 'json'
  });
  
  const response = await fetch(`${baseURL}/services/search/jobs/oneshot`, {
    method: 'POST',
    headers,
    body: searchParams
  });
  
  return await response.json();
};
```

#### Common Splunk Queries for SOC

```splunk
# Security Events by Severity
index=security | stats count by severity | sort -count

# Failed Authentication Attempts
index=security sourcetype=auth action=failure 
| stats count by src_ip, user 
| where count > 5 
| sort -count

# Malware Detections
index=security sourcetype=antivirus signature=*
| eval threat_name=case(
    match(signature, "Trojan"), "Trojan",
    match(signature, "Virus"), "Virus",
    match(signature, "Malware"), "Malware",
    1=1, "Other"
)
| stats count by threat_name, src_host
| sort -count

# Network Anomalies
index=security sourcetype=firewall action=blocked
| bucket _time span=5m
| stats count by _time, dest_port
| where count > 100
| sort -_time

# Data Exfiltration Detection
index=security sourcetype=proxy
| where bytes_out > 1000000
| stats sum(bytes_out) as total_bytes by src_ip, dest_host
| where total_bytes > 10000000
| sort -total_bytes
```

### Elasticsearch Integration

#### Connection Setup
```typescript
import { Client } from '@elastic/elasticsearch';

const elasticClient = new Client({
  node: process.env.ELASTIC_URL,
  auth: {
    apiKey: process.env.ELASTIC_API_KEY
  },
  tls: {
    rejectUnauthorized: false // Only for development
  }
});

// Test connection
const testConnection = async () => {
  try {
    const health = await elasticClient.cluster.health();
    console.log('Elasticsearch cluster health:', health.body);
  } catch (error) {
    console.error('Elasticsearch connection failed:', error);
  }
};
```

#### Security Event Queries

**Recent Alerts Query**
```typescript
const getRecentAlerts = async (timeRange: string = '1h') => {
  const query = {
    index: 'security-*',
    body: {
      query: {
        bool: {
          must: [
            {
              range: {
                '@timestamp': {
                  gte: `now-${timeRange}`
                }
              }
            },
            {
              term: {
                'event.category': 'security'
              }
            }
          ]
        }
      },
      sort: [
        {
          '@timestamp': {
            order: 'desc'
          }
        }
      ],
      size: 100
    }
  };
  
  const response = await elasticClient.search(query);
  return response.body.hits.hits;
};
```

**Aggregation Queries**
```typescript
const getSecurityMetrics = async () => {
  const query = {
    index: 'security-*',
    body: {
      size: 0,
      aggs: {
        severity_distribution: {
          terms: {
            field: 'alert.severity.keyword',
            size: 10
          }
        },
        events_over_time: {
          date_histogram: {
            field: '@timestamp',
            calendar_interval: '1h'
          }
        },
        top_source_ips: {
          terms: {
            field: 'source.ip',
            size: 10
          }
        }
      }
    }
  };
  
  const response = await elasticClient.search(query);
  return response.body.aggregations;
};
```

**Complex Security Queries**
```typescript
// Detect potential brute force attacks
const detectBruteForce = async () => {
  return await elasticClient.search({
    index: 'security-*',
    body: {
      query: {
        bool: {
          must: [
            { term: { 'event.action': 'authentication_failure' } },
            { range: { '@timestamp': { gte: 'now-1h' } } }
          ]
        }
      },
      aggs: {
        by_source_ip: {
          terms: {
            field: 'source.ip',
            min_doc_count: 10,
            size: 20
          },
          aggs: {
            unique_users: {
              cardinality: {
                field: 'user.name.keyword'
              }
            }
          }
        }
      }
    }
  });
};

// Identify data exfiltration patterns
const detectDataExfiltration = async () => {
  return await elasticClient.search({
    index: 'network-*',
    body: {
      query: {
        bool: {
          must: [
            { range: { 'network.bytes': { gte: 1000000 } } },
            { range: { '@timestamp': { gte: 'now-24h' } } }
          ]
        }
      },
      aggs: {
        by_source: {
          terms: {
            field: 'source.ip',
            size: 10
          },
          aggs: {
            total_bytes: {
              sum: {
                field: 'network.bytes'
              }
            },
            unique_destinations: {
              cardinality: {
                field: 'destination.ip'
              }
            }
          }
        }
      }
    }
  });
};
```

### QRadar API Integration

#### Authentication and Setup
```typescript
const qradarConfig = {
  baseURL: 'https://your-qradar-server',
  token: 'your-api-token',
  version: '12.0'
};

const qradarHeaders = {
  'SEC': qradarConfig.token,
  'Version': qradarConfig.version,
  'Accept': 'application/json',
  'Content-Type': 'application/json'
};
```

#### Offense Management
```typescript
// Get recent offenses
const getOffenses = async (filters?: any) => {
  const params = new URLSearchParams({
    filter: filters?.severity ? `severity>${filters.severity}` : '',
    sort: '-start_time',
    Range: 'items=0-49'
  });
  
  const response = await fetch(
    `${qradarConfig.baseURL}/api/siem/offenses?${params}`,
    { headers: qradarHeaders }
  );
  
  return await response.json();
};

// Get offense details
const getOffenseDetails = async (offenseId: number) => {
  const response = await fetch(
    `${qradarConfig.baseURL}/api/siem/offenses/${offenseId}`,
    { headers: qradarHeaders }
  );
  
  return await response.json();
};

// Update offense status
const updateOffenseStatus = async (offenseId: number, status: string) => {
  const response = await fetch(
    `${qradarConfig.baseURL}/api/siem/offenses/${offenseId}`,
    {
      method: 'POST',
      headers: qradarHeaders,
      body: JSON.stringify({
        status: status,
        closing_reason_id: status === 'CLOSED' ? 1 : undefined
      })
    }
  );
  
  return await response.json();
};
```

#### AQL (Ariel Query Language) Searches
```typescript
const executeAQLSearch = async (aqlQuery: string) => {
  // Create search
  const searchResponse = await fetch(
    `${qradarConfig.baseURL}/api/ariel/searches`,
    {
      method: 'POST',
      headers: qradarHeaders,
      body: JSON.stringify({
        query_expression: aqlQuery
      })
    }
  );
  
  const searchResult = await searchResponse.json();
  const searchId = searchResult.search_id;
  
  // Poll for completion
  let completed = false;
  while (!completed) {
    const statusResponse = await fetch(
      `${qradarConfig.baseURL}/api/ariel/searches/${searchId}`,
      { headers: qradarHeaders }
    );
    
    const status = await statusResponse.json();
    completed = status.status === 'COMPLETED';
    
    if (!completed) {
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
  }
  
  // Get results
  const resultsResponse = await fetch(
    `${qradarConfig.baseURL}/api/ariel/searches/${searchId}/results`,
    { headers: qradarHeaders }
  );
  
  return await resultsResponse.json();
};
```

**Common AQL Queries**
```sql
-- High severity events in last hour
SELECT sourceip, destinationip, eventname, magnitude 
FROM events 
WHERE magnitude > 7 
LAST 1 HOURS

-- Failed login attempts by source IP
SELECT sourceip, COUNT(*) as attempt_count
FROM events 
WHERE eventname ILIKE '%authentication%' 
AND eventname ILIKE '%fail%'
GROUP BY sourceip 
HAVING COUNT(*) > 10
LAST 24 HOURS

-- Network connections to suspicious destinations
SELECT sourceip, destinationip, destinationport, COUNT(*) as connection_count
FROM flows 
WHERE destinationip IN (
  SELECT sourceip FROM events WHERE category = 1001
)
GROUP BY sourceip, destinationip, destinationport
LAST 1 HOURS

-- Data volume analysis
SELECT sourceip, SUM(sourcebytes + destinationbytes) as total_bytes
FROM flows 
WHERE (sourcebytes + destinationbytes) > 1000000
GROUP BY sourceip 
ORDER BY total_bytes DESC
LAST 24 HOURS
```

## 🧠 Threat Intelligence APIs

### MISP Integration

#### Event Management
```typescript
// Search for indicators
const searchIndicators = async (value: string, type: string) => {
  const response = await fetch(`${mispConfig.url}/attributes/restSearch`, {
    method: 'POST',
    headers: {
      'Authorization': mispConfig.apiKey,
      'Accept': 'application/json',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      value: value,
      type: type,
      limit: 10,
      page: 1
    })
  });
  
  return await response.json();
};

// Get event details
const getEventDetails = async (eventId: string) => {
  const response = await fetch(`${mispConfig.url}/events/${eventId}`, {
    headers: {
      'Authorization': mispConfig.apiKey,
      'Accept': 'application/json'
    }
  });
  
  return await response.json();
};

// Add new indicator
const addIndicator = async (eventId: string, indicator: any) => {
  const response = await fetch(`${mispConfig.url}/attributes/add/${eventId}`, {
    method: 'POST',
    headers: {
      'Authorization': mispConfig.apiKey,
      'Accept': 'application/json',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      type: indicator.type,
      value: indicator.value,
      category: indicator.category,
      to_ids: true,
      comment: indicator.comment
    })
  });
  
  return await response.json();
};
```

### VirusTotal API v3

#### File Analysis
```typescript
const analyzeFile = async (fileHash: string) => {
  const response = await fetch(`https://www.virustotal.com/vtapi/v2/file/report`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: new URLSearchParams({
      apikey: vtConfig.apiKey,
      resource: fileHash
    })
  });
  
  return await response.json();
};

// URL Analysis
const analyzeURL = async (url: string) => {
  const response = await fetch(`https://www.virustotal.com/vtapi/v2/url/report`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: new URLSearchParams({
      apikey: vtConfig.apiKey,
      resource: url
    })
  });
  
  return await response.json();
};

// IP Address Analysis
const analyzeIP = async (ip: string) => {
  const response = await fetch(`https://www.virustotal.com/vtapi/v2/ip-address/report`, {
    method: 'GET',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    }
  });
  
  const params = new URLSearchParams({
    apikey: vtConfig.apiKey,
    ip: ip
  });
  
  const fullResponse = await fetch(`${response.url}?${params}`);
  return await fullResponse.json();
};
```

### AlienVault OTX Integration

#### Pulse and Indicator Queries
```typescript
// Get pulses by indicator
const getPulsesByIndicator = async (indicator: string, type: string) => {
  const endpoint = getOTXEndpoint(type);
  const response = await fetch(
    `https://otx.alienvault.com/api/v1/indicators/${endpoint}/${indicator}/general`,
    {
      headers: {
        'X-OTX-API-KEY': otxConfig.apiKey
      }
    }
  );
  
  return await response.json();
};

// Get detailed pulse information
const getPulseDetails = async (pulseId: string) => {
  const response = await fetch(
    `https://otx.alienvault.com/api/v1/pulses/${pulseId}`,
    {
      headers: {
        'X-OTX-API-KEY': otxConfig.apiKey
      }
    }
  );
  
  return await response.json();
};

// Search pulses by keyword
const searchPulses = async (query: string) => {
  const response = await fetch(
    `https://otx.alienvault.com/api/v1/pulses/subscribed?q=${encodeURIComponent(query)}`,
    {
      headers: {
        'X-OTX-API-KEY': otxConfig.apiKey
      }
    }
  );
  
  return await response.json();
};
```

## 🔔 Notification APIs

### Slack Integration

#### Advanced Message Formatting
```typescript
const sendRichSlackAlert = async (alert: SecurityAlert) => {
  const payload = {
    channel: slackConfig.channel,
    username: 'SecOps Bot',
    icon_emoji: ':shield:',
    attachments: [{
      color: getSeverityColor(alert.severity),
      title: `🚨 ${alert.title}`,
      title_link: `${dashboardURL}/alerts/${alert.id}`,
      text: alert.description,
      fields: [
        {
          title: 'Severity',
          value: alert.severity.toUpperCase(),
          short: true
        },
        {
          title: 'Source',
          value: alert.source,
          short: true
        },
        {
          title: 'Affected Assets',
          value: alert.affectedAssets?.join(', ') || 'Unknown',
          short: false
        }
      ],
      actions: [
        {
          type: 'button',
          text: 'Acknowledge',
          url: `${dashboardURL}/alerts/${alert.id}/acknowledge`,
          style: 'primary'
        },
        {
          type: 'button',
          text: 'Investigate',
          url: `${dashboardURL}/alerts/${alert.id}/investigate`,
          style: 'danger'
        }
      ],
      footer: 'SecOps Dashboard',
      footer_icon: 'https://your-domain.com/favicon.ico',
      ts: Math.floor(alert.timestamp.getTime() / 1000)
    }]
  };
  
  const response = await fetch(slackConfig.webhookUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  
  return response.ok;
};
```

### Microsoft Teams Integration

#### Adaptive Cards
```typescript
const sendTeamsAdaptiveCard = async (alert: SecurityAlert) => {
  const card = {
    type: 'message',
    attachments: [{
      contentType: 'application/vnd.microsoft.card.adaptive',
      content: {
        type: 'AdaptiveCard',
        version: '1.3',
        body: [
          {
            type: 'TextBlock',
            text: `🚨 Security Alert: ${alert.title}`,
            weight: 'Bolder',
            size: 'Medium',
            color: getSeverityColor(alert.severity)
          },
          {
            type: 'FactSet',
            facts: [
              { title: 'Severity:', value: alert.severity.toUpperCase() },
              { title: 'Source:', value: alert.source },
              { title: 'Time:', value: alert.timestamp.toISOString() },
              { title: 'Status:', value: alert.status }
            ]
          },
          {
            type: 'TextBlock',
            text: alert.description,
            wrap: true
          }
        ],
        actions: [
          {
            type: 'Action.OpenUrl',
            title: 'View in Dashboard',
            url: `${dashboardURL}/alerts/${alert.id}`
          },
          {
            type: 'Action.OpenUrl',
            title: 'Acknowledge',
            url: `${dashboardURL}/alerts/${alert.id}/acknowledge`
          }
        ]
      }
    }]
  };
  
  const response = await fetch(teamsConfig.webhookUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(card)
  });
  
  return response.ok;
};
```

## 📊 Metrics and Monitoring APIs

### Prometheus Metrics Collection

#### Custom Metrics
```typescript
import { register, Counter, Histogram, Gauge } from 'prom-client';

// Security-specific metrics
const securityMetrics = {
  alertsTotal: new Counter({
    name: 'security_alerts_total',
    help: 'Total number of security alerts',
    labelNames: ['severity', 'source', 'status']
  }),
  
  incidentResponseTime: new Histogram({
    name: 'incident_response_time_seconds',
    help: 'Time taken to respond to incidents',
    labelNames: ['severity', 'type'],
    buckets: [1, 5, 15, 30, 60, 300, 900, 1800, 3600]
  }),
  
  activeThreats: new Gauge({
    name: 'active_threats_current',
    help: 'Current number of active threats',
    labelNames: ['type', 'severity']
  }),
  
  falsePositiveRate: new Gauge({
    name: 'false_positive_rate',
    help: 'Current false positive rate',
    labelNames: ['source', 'rule_type']
  })
};

// Metric collection functions
export const recordAlert = (severity: string, source: string, status: string) => {
  securityMetrics.alertsTotal.labels(severity, source, status).inc();
};

export const recordIncidentResponse = (severity: string, type: string, responseTime: number) => {
  securityMetrics.incidentResponseTime.labels(severity, type).observe(responseTime);
};

export const updateActiveThreats = (type: string, severity: string, count: number) => {
  securityMetrics.activeThreats.labels(type, severity).set(count);
};
```

### Health Check Endpoints
```typescript
// Comprehensive health check
export const healthCheck = async (): Promise<HealthStatus> => {
  const checks = await Promise.allSettled([
    checkDatabase(),
    checkRedis(),
    checkElasticsearch(),
    checkSIEMConnections(),
    checkThreatIntelFeeds()
  ]);
  
  const results = checks.map((check, index) => ({
    service: ['database', 'redis', 'elasticsearch', 'siem', 'threat_intel'][index],
    status: check.status === 'fulfilled' ? 'healthy' : 'unhealthy',
    details: check.status === 'fulfilled' ? check.value : check.reason
  }));
  
  const overallStatus = results.every(r => r.status === 'healthy') ? 'healthy' : 'degraded';
  
  return {
    status: overallStatus,
    timestamp: new Date().toISOString(),
    services: results,
    version: process.env.APP_VERSION || 'unknown'
  };
};

// Individual service checks
const checkDatabase = async () => {
  const start = Date.now();
  await mongoose.connection.db.admin().ping();
  return { responseTime: Date.now() - start };
};

const checkRedis = async () => {
  const start = Date.now();
  await redisClient.ping();
  return { responseTime: Date.now() - start };
};

const checkElasticsearch = async () => {
  const start = Date.now();
  const health = await elasticClient.cluster.health();
  return { 
    responseTime: Date.now() - start,
    clusterStatus: health.body.status
  };
};
```

## 🔐 Security API Best Practices

### Rate Limiting
```typescript
import rateLimit from 'express-rate-limit';

// Different limits for different endpoints
const createRateLimit = (windowMs: number, max: number) => rateLimit({
  windowMs,
  max,
  message: 'Too many requests from this IP',
  standardHeaders: true,
  legacyHeaders: false
});

// Apply to routes
app.use('/api/auth', createRateLimit(15 * 60 * 1000, 5)); // 5 attempts per 15 minutes
app.use('/api/alerts', createRateLimit(60 * 1000, 100)); // 100 requests per minute
app.use('/api/search', createRateLimit(60 * 1000, 20)); // 20 searches per minute
```

### Input Validation
```typescript
import Joi from 'joi';

const alertSchema = Joi.object({
  title: Joi.string().min(1).max(200).required(),
  severity: Joi.string().valid('low', 'medium', 'high', 'critical').required(),
  source: Joi.string().min(1).max(100).required(),
  description: Joi.string().max(1000),
  tags: Joi.array().items(Joi.string().max(50)).max(10),
  sourceIP: Joi.string().ip(),
  destinationIP: Joi.string().ip()
});

export const validateAlert = (req: Request, res: Response, next: NextFunction) => {
  const { error } = alertSchema.validate(req.body);
  if (error) {
    return res.status(400).json({ error: error.details[0].message });
  }
  next();
};
```

### API Response Standardization
```typescript
interface APIResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  metadata?: {
    total?: number;
    page?: number;
    limit?: number;
    timestamp: string;
  };
}

export const sendResponse = <T>(
  res: Response, 
  data: T, 
  status: number = 200,
  metadata?: any
): void => {
  const response: APIResponse<T> = {
    success: status < 400,
    data: status < 400 ? data : undefined,
    error: status >= 400 ? (data as any) : undefined,
    metadata: {
      ...metadata,
      timestamp: new Date().toISOString()
    }
  };
  
  res.status(status).json(response);
};
```

This completes the comprehensive API integration guide. Each section provides practical examples and best practices for integrating with real security infrastructure.
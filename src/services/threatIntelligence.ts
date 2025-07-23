import config from '../config/environment';

interface ThreatIntelResult {
  ioc: string;
  type: 'ip' | 'domain' | 'hash' | 'url';
  reputation: 'malicious' | 'suspicious' | 'clean' | 'unknown';
  confidence: number;
  sources: string[];
  details: any;
  lastSeen?: Date;
  tags?: string[];
}

class ThreatIntelligenceService {
  
  // MISP Integration
  async queryMISP(ioc: string, type: string): Promise<ThreatIntelResult | null> {
    try {
      const response = await fetch(`${config.threatIntel.misp.url}/attributes/restSearch`, {
        method: 'POST',
        headers: {
          'Authorization': config.threatIntel.misp.apiKey,
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        body: JSON.stringify({
          value: ioc,
          type: type,
          limit: 1,
        }),
      });

      const data = await response.json();
      
      if (data.response?.Attribute?.length > 0) {
        const attr = data.response.Attribute[0];
        return {
          ioc,
          type: type as any,
          reputation: attr.to_ids ? 'malicious' : 'suspicious',
          confidence: 0.8,
          sources: ['MISP'],
          details: attr,
          lastSeen: new Date(attr.timestamp * 1000),
          tags: attr.Tag?.map((t: any) => t.name) || [],
        };
      }
      
      return null;
    } catch (error) {
      console.error('MISP query failed:', error);
      return null;
    }
  }

  // AlienVault OTX Integration
  async queryOTX(ioc: string, type: string): Promise<ThreatIntelResult | null> {
    try {
      const endpoint = this.getOTXEndpoint(type);
      const response = await fetch(`https://otx.alienvault.com/api/v1/indicators/${endpoint}/${ioc}/general`, {
        headers: {
          'X-OTX-API-KEY': config.threatIntel.otx.apiKey,
        },
      });

      const data = await response.json();
      
      if (data.pulse_info?.count > 0) {
        return {
          ioc,
          type: type as any,
          reputation: data.reputation ? 'malicious' : 'suspicious',
          confidence: 0.7,
          sources: ['AlienVault OTX'],
          details: data,
          tags: data.pulse_info.pulses?.map((p: any) => p.name).slice(0, 5) || [],
        };
      }
      
      return null;
    } catch (error) {
      console.error('OTX query failed:', error);
      return null;
    }
  }

  // VirusTotal Integration
  async queryVirusTotal(ioc: string, type: string): Promise<ThreatIntelResult | null> {
    try {
      const endpoint = this.getVTEndpoint(type);
      const response = await fetch(`https://www.virustotal.com/vtapi/v2/${endpoint}/report`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          apikey: config.threatIntel.virustotal.apiKey,
          resource: ioc,
        }),
      });

      const data = await response.json();
      
      if (data.response_code === 1) {
        const positives = data.positives || 0;
        const total = data.total || 1;
        const ratio = positives / total;
        
        let reputation: ThreatIntelResult['reputation'] = 'clean';
        if (ratio > 0.3) reputation = 'malicious';
        else if (ratio > 0.1) reputation = 'suspicious';
        
        return {
          ioc,
          type: type as any,
          reputation,
          confidence: Math.min(0.9, ratio * 2),
          sources: ['VirusTotal'],
          details: data,
          tags: [`${positives}/${total} detections`],
        };
      }
      
      return null;
    } catch (error) {
      console.error('VirusTotal query failed:', error);
      return null;
    }
  }

  // Aggregate threat intelligence from multiple sources
  async enrichIOC(ioc: string, type: 'ip' | 'domain' | 'hash' | 'url'): Promise<ThreatIntelResult> {
    const results = await Promise.allSettled([
      this.queryMISP(ioc, type),
      this.queryOTX(ioc, type),
      this.queryVirusTotal(ioc, type),
    ]);

    const validResults = results
      .filter((result): result is PromiseFulfilledResult<ThreatIntelResult> => 
        result.status === 'fulfilled' && result.value !== null
      )
      .map(result => result.value);

    if (validResults.length === 0) {
      return {
        ioc,
        type,
        reputation: 'unknown',
        confidence: 0,
        sources: [],
        details: {},
      };
    }

    // Aggregate results
    const aggregated: ThreatIntelResult = {
      ioc,
      type,
      reputation: this.aggregateReputation(validResults),
      confidence: this.aggregateConfidence(validResults),
      sources: validResults.flatMap(r => r.sources),
      details: validResults.reduce((acc, r) => ({ ...acc, ...r.details }), {}),
      lastSeen: validResults
        .map(r => r.lastSeen)
        .filter(Boolean)
        .sort((a, b) => (b?.getTime() || 0) - (a?.getTime() || 0))[0],
      tags: [...new Set(validResults.flatMap(r => r.tags || []))],
    };

    return aggregated;
  }

  // Bulk IOC enrichment
  async enrichIOCs(iocs: Array<{ value: string; type: 'ip' | 'domain' | 'hash' | 'url' }>): Promise<ThreatIntelResult[]> {
    const promises = iocs.map(({ value, type }) => this.enrichIOC(value, type));
    return Promise.all(promises);
  }

  private aggregateReputation(results: ThreatIntelResult[]): ThreatIntelResult['reputation'] {
    const reputations = results.map(r => r.reputation);
    
    if (reputations.includes('malicious')) return 'malicious';
    if (reputations.includes('suspicious')) return 'suspicious';
    if (reputations.includes('clean')) return 'clean';
    return 'unknown';
  }

  private aggregateConfidence(results: ThreatIntelResult[]): number {
    if (results.length === 0) return 0;
    
    const avgConfidence = results.reduce((sum, r) => sum + r.confidence, 0) / results.length;
    const sourceBonus = Math.min(0.2, results.length * 0.1);
    
    return Math.min(1, avgConfidence + sourceBonus);
  }

  private getOTXEndpoint(type: string): string {
    const mapping: { [key: string]: string } = {
      'ip': 'IPv4',
      'domain': 'domain',
      'hash': 'file',
      'url': 'url',
    };
    return mapping[type] || 'IPv4';
  }

  private getVTEndpoint(type: string): string {
    const mapping: { [key: string]: string } = {
      'ip': 'ip-address',
      'domain': 'domain',
      'hash': 'file',
      'url': 'url',
    };
    return mapping[type] || 'file';
  }
}

export const threatIntelService = new ThreatIntelligenceService();
export default threatIntelService;
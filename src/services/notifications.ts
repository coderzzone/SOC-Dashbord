import config from '../config/environment';

interface NotificationPayload {
  title: string;
  message: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  source?: string;
  timestamp?: Date;
  metadata?: any;
}

class NotificationService {
  
  // Send notification to all configured channels
  async sendNotification(payload: NotificationPayload) {
    const promises = [];

    if (config.notifications.slack.webhookUrl) {
      promises.push(this.sendSlackNotification(payload));
    }

    if (config.notifications.teams.webhookUrl) {
      promises.push(this.sendTeamsNotification(payload));
    }

    if (config.notifications.email.smtpHost) {
      promises.push(this.sendEmailNotification(payload));
    }

    const results = await Promise.allSettled(promises);
    
    // Log any failures
    results.forEach((result, index) => {
      if (result.status === 'rejected') {
        console.error(`Notification ${index} failed:`, result.reason);
      }
    });

    return results;
  }

  // Slack integration
  async sendSlackNotification(payload: NotificationPayload) {
    const color = this.getSeverityColor(payload.severity);
    const emoji = this.getSeverityEmoji(payload.severity);
    
    const slackPayload = {
      channel: config.notifications.slack.channel,
      username: 'SecOps Bot',
      icon_emoji: ':shield:',
      attachments: [{
        color,
        title: `${emoji} ${payload.title}`,
        text: payload.message,
        fields: [
          {
            title: 'Severity',
            value: payload.severity.toUpperCase(),
            short: true,
          },
          {
            title: 'Source',
            value: payload.source || 'Unknown',
            short: true,
          },
          {
            title: 'Timestamp',
            value: (payload.timestamp || new Date()).toISOString(),
            short: false,
          },
        ],
        footer: 'SecOps Dashboard',
        ts: Math.floor((payload.timestamp || new Date()).getTime() / 1000),
      }],
    };

    const response = await fetch(config.notifications.slack.webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(slackPayload),
    });

    if (!response.ok) {
      throw new Error(`Slack notification failed: ${response.statusText}`);
    }

    return response;
  }

  // Microsoft Teams integration
  async sendTeamsNotification(payload: NotificationPayload) {
    const color = this.getSeverityColor(payload.severity);
    
    const teamsPayload = {
      '@type': 'MessageCard',
      '@context': 'https://schema.org/extensions',
      summary: payload.title,
      themeColor: color.replace('#', ''),
      sections: [{
        activityTitle: payload.title,
        activitySubtitle: `Severity: ${payload.severity.toUpperCase()}`,
        activityImage: 'https://via.placeholder.com/64x64/0078d4/ffffff?text=🛡️',
        facts: [
          { name: 'Message', value: payload.message },
          { name: 'Source', value: payload.source || 'Unknown' },
          { name: 'Timestamp', value: (payload.timestamp || new Date()).toISOString() },
        ],
        markdown: true,
      }],
      potentialAction: [{
        '@type': 'OpenUri',
        name: 'View in Dashboard',
        targets: [{
          os: 'default',
          uri: window.location.origin,
        }],
      }],
    };

    const response = await fetch(config.notifications.teams.webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(teamsPayload),
    });

    if (!response.ok) {
      throw new Error(`Teams notification failed: ${response.statusText}`);
    }

    return response;
  }

  // Email notification (requires backend SMTP service)
  async sendEmailNotification(payload: NotificationPayload) {
    const emailPayload = {
      to: ['soc-team@company.com'], // Configure recipient list
      subject: `[${payload.severity.toUpperCase()}] ${payload.title}`,
      html: this.generateEmailHTML(payload),
    };

    // This would typically go through your backend API
    const response = await fetch('/api/notifications/email', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(emailPayload),
    });

    if (!response.ok) {
      throw new Error(`Email notification failed: ${response.statusText}`);
    }

    return response;
  }

  // Browser push notification
  async sendBrowserNotification(payload: NotificationPayload) {
    if (!('Notification' in window)) {
      console.warn('Browser notifications not supported');
      return;
    }

    if (Notification.permission === 'granted') {
      new Notification(payload.title, {
        body: payload.message,
        icon: '/favicon.ico',
        badge: '/favicon.ico',
        tag: `security-alert-${Date.now()}`,
        requireInteraction: payload.severity === 'critical',
      });
    } else if (Notification.permission !== 'denied') {
      const permission = await Notification.requestPermission();
      if (permission === 'granted') {
        this.sendBrowserNotification(payload);
      }
    }
  }

  private getSeverityColor(severity: string): string {
    const colors = {
      critical: '#dc2626',
      high: '#ea580c',
      medium: '#d97706',
      low: '#2563eb',
      info: '#059669',
    };
    return colors[severity as keyof typeof colors] || colors.info;
  }

  private getSeverityEmoji(severity: string): string {
    const emojis = {
      critical: '🚨',
      high: '⚠️',
      medium: '⚡',
      low: 'ℹ️',
      info: '📋',
    };
    return emojis[severity as keyof typeof emojis] || emojis.info;
  }

  private generateEmailHTML(payload: NotificationPayload): string {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Security Alert</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
          .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
          .header { background: ${this.getSeverityColor(payload.severity)}; color: white; padding: 20px; text-align: center; }
          .content { padding: 20px; }
          .footer { background: #f8f9fa; padding: 15px; text-align: center; font-size: 12px; color: #666; }
          .severity { display: inline-block; padding: 4px 8px; border-radius: 4px; font-weight: bold; text-transform: uppercase; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>${payload.title}</h1>
            <span class="severity">${payload.severity}</span>
          </div>
          <div class="content">
            <p><strong>Message:</strong> ${payload.message}</p>
            <p><strong>Source:</strong> ${payload.source || 'Unknown'}</p>
            <p><strong>Timestamp:</strong> ${(payload.timestamp || new Date()).toLocaleString()}</p>
            ${payload.metadata ? `<p><strong>Additional Details:</strong> ${JSON.stringify(payload.metadata, null, 2)}</p>` : ''}
          </div>
          <div class="footer">
            <p>This alert was generated by SecOps Dashboard</p>
            <p><a href="${window.location.origin}">View Dashboard</a></p>
          </div>
        </div>
      </body>
      </html>
    `;
  }
}

export const notificationService = new NotificationService();
export default notificationService;
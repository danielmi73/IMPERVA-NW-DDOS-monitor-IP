import nodemailer from 'nodemailer';
import { getSettings } from '../db.js';

/**
 * Creates a Nodemailer transporter based on current or provided settings
 */
export function createTransporter(customSettings = null) {
  const settings = customSettings || getSettings();

  const port = parseInt(settings.smtp_port || '587', 10);
  const encryption = (settings.smtp_encryption || 'tls').toLowerCase();
  const secure = encryption === 'ssl' || port === 465;

  const transportConfig = {
    host: settings.smtp_host,
    port: port,
    secure: secure,
    connectionTimeout: 10000,
    greetingTimeout: 10000,
    socketTimeout: 15000,
  };

  if (settings.smtp_user) {
    transportConfig.auth = {
      user: settings.smtp_user,
      pass: settings.smtp_pass || ''
    };
  }

  // Handle TLS options
  if (encryption === 'tls' || encryption === 'starttls') {
    transportConfig.requireTLS = true;
    transportConfig.tls = {
      rejectUnauthorized: false // Allow self-signed or internal enterprise certs if needed
    };
  } else if (encryption === 'none') {
    transportConfig.ignoreTLS = true;
  }

  return nodemailer.createTransport(transportConfig);
}

/**
 * Render email subject and body with placeholders
 */
export function renderEmailContent(templateSubject, templateBody, blockedEvents, settings) {
  const count = blockedEvents.length;
  const timestamp = new Date().toUTCString();
  const accountId = settings.account_id || 'N/A';
  const ipList = blockedEvents.map(e => e.source_ip).join(', ');

  const eventRowsHtml = blockedEvents.map(e => `
    <tr>
      <td style="padding: 8px; border: 1px solid #ddd; font-family: monospace; font-size: 13px;">${e.timestamp || new Date().toISOString()}</td>
      <td style="padding: 8px; border: 1px solid #ddd; font-family: monospace; font-weight: bold; color: #d32f2f;">${e.source_ip}</td>
      <td style="padding: 8px; border: 1px solid #ddd;">${e.description || 'N/A'}</td>
      <td style="padding: 8px; border: 1px solid #ddd; font-family: monospace;">${e.network_range || 'N/A'}</td>
      <td style="padding: 8px; border: 1px solid #ddd; font-weight: bold;">${e.bandwidth_human || `${e.bandwidth_bps} bps`}</td>
    </tr>
  `).join('');

  const fullTableHtml = `
    <table border="1" cellpadding="8" cellspacing="0" style="border-collapse: collapse; width: 100%; font-family: sans-serif; font-size: 14px;">
      <thead style="background-color: #f8f9fa;">
        <tr>
          <th style="padding: 8px; border: 1px solid #ddd; text-align: left;">Timestamp</th>
          <th style="padding: 8px; border: 1px solid #ddd; text-align: left;">Blocked Source IP</th>
          <th style="padding: 8px; border: 1px solid #ddd; text-align: left;">Description</th>
          <th style="padding: 8px; border: 1px solid #ddd; text-align: left;">Network Range</th>
          <th style="padding: 8px; border: 1px solid #ddd; text-align: left;">Peak Bandwidth</th>
        </tr>
      </thead>
      <tbody>
        ${eventRowsHtml}
      </tbody>
    </table>
  `;

  // Placeholders replacement
  const replacements = {
    '{count}': String(count),
    '{timestamp}': timestamp,
    '{account_id}': accountId,
    '{ip_list}': ipList,
    '{event_rows}': eventRowsHtml,
    '{table}': fullTableHtml
  };

  let subject = templateSubject || '🚨 [DDoS Alert] Blocked Monitored IP Detected: {count} IP(s)';
  let body = templateBody || fullTableHtml;

  for (const [placeholder, val] of Object.entries(replacements)) {
    subject = subject.replaceAll(placeholder, val);
    body = body.replaceAll(placeholder, val);
  }

  return { subject, body };
}

/**
 * Send test email
 */
export async function sendTestEmail(customSettings = null, recipientEmail = null) {
  const settings = customSettings || getSettings();
  const to = recipientEmail || settings.smtp_recipients;

  if (!settings.smtp_host) {
    throw new Error('SMTP Server host is not configured.');
  }
  if (!to) {
    throw new Error('No recipient email specified.');
  }

  const transporter = createTransporter(settings);

  const testEvent = [{
    timestamp: new Date().toISOString(),
    source_ip: '198.51.100.42',
    description: 'Test Monitored Node',
    network_range: '198.51.100.0/24',
    bandwidth_bps: 45000000,
    bandwidth_human: '45.00 Mbps'
  }];

  const { subject, body } = renderEmailContent(
    settings.email_subject_template ? `[TEST] ${settings.email_subject_template}` : '[TEST] DDoS Notification Tool Alert',
    settings.email_body_template,
    testEvent,
    settings
  );

  const info = await transporter.sendMail({
    from: settings.smtp_sender || 'ddos-alerts@imperva-monitor.local',
    to: to,
    subject: subject,
    html: `
      <div style="padding: 10px; margin-bottom: 15px; background: #e3f2fd; border-left: 4px solid #2196f3; font-family: sans-serif;">
        <strong>Notice:</strong> This is a test email sent from the DDoS Notification Tool Admin Console to verify your SMTP configuration.
      </div>
      ${body}
    `
  });

  return {
    success: true,
    messageId: info.messageId,
    response: info.response
  };
}

/**
 * Send alert email for detected blocked IPs (batch or single)
 */
export async function sendBlockAlertEmail(blockedEvents) {
  if (!blockedEvents || blockedEvents.length === 0) return { success: false, reason: 'No events' };

  const settings = getSettings();
  if (!settings.smtp_host || !settings.smtp_recipients) {
    console.warn('[EmailService] SMTP host or recipients not configured. Skipping email dispatch.');
    return { success: false, reason: 'SMTP not configured' };
  }

  try {
    const transporter = createTransporter(settings);
    const { subject, body } = renderEmailContent(
      settings.email_subject_template,
      settings.email_body_template,
      blockedEvents,
      settings
    );

    const info = await transporter.sendMail({
      from: settings.smtp_sender || 'ddos-alerts@imperva-monitor.local',
      to: settings.smtp_recipients,
      subject: subject,
      html: body
    });

    console.log(`[EmailService] Alert email sent for ${blockedEvents.length} blocked IP(s). Message ID: ${info.messageId}`);
    return { success: true, messageId: info.messageId };
  } catch (err) {
    console.error('[EmailService] Failed to send alert email:', err.message);
    return { success: false, error: err.message };
  }
}

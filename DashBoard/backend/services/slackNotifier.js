const fetch = require('node-fetch');

const SLACK_WEBHOOK_URL = process.env.SLACK_WEBHOOK_URL;
const severityColors = {
  critical: '#8B0000',
  high: '#D7263D',
  medium: '#F2C438',
  low: '#36A64F'
};

let missingWebhookWarned = false;

const truncate = (text = '', maxLength = 500) => {
  if (!text) return null;
  if (text.length <= maxLength) return text;
  return `${text.slice(0, maxLength - 3)}...`;
};

const postToSlack = async (payload) => {
  if (!SLACK_WEBHOOK_URL) {
    if (!missingWebhookWarned) {
      console.warn('[SlackNotifier] SLACK_WEBHOOK_URL이 설정되지 않아 알림을 보낼 수 없습니다.');
      missingWebhookWarned = true;
    }
    return;
  }

  try {
    const response = await fetch(SLACK_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('[SlackNotifier] Slack 전송 실패:', errorText);
    }
  } catch (error) {
    console.error('[SlackNotifier] Slack 전송 오류:', error.message);
  }
};

const buildAttachment = (title, severity, fields = []) => ({
  color: severityColors[severity] || severityColors.medium,
  title,
  fields: fields.filter(Boolean),
  footer: 'MCP Dashboard',
  ts: Math.floor(Date.now() / 1000)
});

const notifyDlpViolation = async (log) => {
  if (!log) return;

  const severity = log.severity || 'medium';
  const payload = {
    text: `🚨 DLP 위반 감지 (${severity.toUpperCase()})`,
    attachments: [
      buildAttachment('DLP Violation Detected', severity, [
        log.username ? { title: '사용자', value: log.username, short: true } : null,
        log.employee_id ? { title: '사번', value: log.employee_id, short: true } : null,
        log.source_ip ? { title: 'IP', value: log.source_ip, short: true } : null,
        log.action_type ? { title: '행동', value: log.action_type, short: true } : null,
        log.violation_type ? { title: '위반 유형', value: log.violation_type, short: true } : null,
        log.id ? { title: '로그 ID', value: String(log.id), short: true } : null,
        log.original_text ? { title: '원문', value: truncate(log.original_text), short: false } : null,
        log.masked_text ? { title: '마스킹', value: truncate(log.masked_text), short: false } : null
      ])
    ]
  };

  await postToSlack(payload);
};

const notifyPermissionViolation = async (log) => {
  if (!log) return;

  const severity = log.severity || 'high';
  const payload = {
    text: `🚨 권한 위반 감지 (${severity.toUpperCase()})`,
    attachments: [
      buildAttachment('Permission Violation Detected', severity, [
        log.username ? { title: '사용자', value: log.username, short: true } : null,
        log.employee_id ? { title: '사번', value: log.employee_id, short: true } : null,
        log.source_ip ? { title: 'IP', value: log.source_ip, short: true } : null,
        log.tool_name ? { title: 'Tool', value: log.tool_name, short: true } : null,
        log.mcp_server_name ? { title: '서버', value: log.mcp_server_name, short: true } : null,
        log.violation_type ? { title: '위반 유형', value: log.violation_type, short: true } : null,
        log.reason ? { title: '사유', value: truncate(log.reason, 300), short: false } : null,
        log.id ? { title: '로그 ID', value: String(log.id), short: true } : null
      ])
    ]
  };

  await postToSlack(payload);
};

module.exports = {
  notifyDlpViolation,
  notifyPermissionViolation
};



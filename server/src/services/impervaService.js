import axios from 'axios';
import { getSettings } from '../db.js';

export function formatBandwidth(bps) {
  if (bps === null || bps === undefined || isNaN(bps)) return '0 bps';
  const num = Number(bps);
  if (num >= 1e9) {
    return `${(num / 1e9).toFixed(2)} Gbps`;
  }
  if (num >= 1e6) {
    return `${(num / 1e6).toFixed(2)} Mbps`;
  }
  if (num >= 1e3) {
    return `${(num / 1e3).toFixed(2)} Kbps`;
  }
  return `${num.toFixed(2)} bps`;
}

/**
 * Fetch protected network prefixes from Imperva API v2
 * GET https://my.imperva.com/api/v2/ddos-protection/account/{account_id}/protected-networks-ids
 */
export async function fetchProtectedNetworks(customCreds = null) {
  const settings = getSettings();
  const accountId = customCreds?.account_id || settings.account_id;
  const apiId = customCreds?.api_id || settings.api_id;
  const apiKey = customCreds?.api_key || settings.api_key;

  if (!accountId || !apiId || !apiKey) {
    throw new Error('Imperva API credentials (Account ID, API ID, API Key) are not configured.');
  }

  const url = `https://my.imperva.com/api/v2/ddos-protection/account/${encodeURIComponent(accountId)}/protected-networks-ids`;

  const response = await axios.get(url, {
    headers: {
      'x-API-Id': apiId,
      'x-API-Key': apiKey,
      'Accept': 'application/json'
    },
    timeout: 15000
  });

  return response.data;
}

/**
 * Fetch top-table blocked source IPs for a network prefix
 * POST https://my.imperva.com/api/v1/infra/top-table
 */
export async function fetchBlockedIpsForPrefix(prefix, startTimeMs, endTimeMs, customCreds = null) {
  const settings = getSettings();
  const accountId = customCreds?.account_id || settings.account_id;
  const apiId = customCreds?.api_id || settings.api_id;
  const apiKey = customCreds?.api_key || settings.api_key;

  if (!accountId || !apiId || !apiKey) {
    throw new Error('Imperva API credentials are not configured.');
  }

  const now = Date.now();
  const end = endTimeMs || now;
  // Default to past 15 minutes window if start is not specified
  const start = startTimeMs || (end - 15 * 60 * 1000);

  const encodedIpRange = encodeURIComponent(prefix);
  const url = `https://my.imperva.com/api/v1/infra/top-table?account_id=${encodeURIComponent(accountId)}&ip_range=${encodedIpRange}&range_type=BGP&start=${start}&end=${end}&data_type=SRC_IP&metric_type=BW&mitigation_type=BLOCK&aggregation_type=PEAK`;

  const response = await axios.post(
    url,
    {},
    {
      headers: {
        'x-API-Id': apiId,
        'x-API-Key': apiKey,
        'Accept': 'application/json'
      },
      timeout: 20000
    }
  );

  return response.data;
}

/**
 * Test Imperva credentials by querying protected networks
 */
export async function testCredentials(creds) {
  try {
    const data = await fetchProtectedNetworks(creds);
    const count = Object.keys(data || {}).length;
    return {
      success: true,
      message: `Authentication successful! Found ${count} protected network prefix(es).`,
      prefixes: data
    };
  } catch (error) {
    let errorMsg = error.response?.data?.res_message || error.response?.data?.message || error.message;
    if (error.response?.status === 401 || error.response?.status === 403) {
      errorMsg = 'Authentication failed: Invalid API ID or API Key.';
    } else if (error.response?.status === 404) {
      errorMsg = 'Account not found: Please check your Account ID.';
    }
    return {
      success: false,
      message: errorMsg
    };
  }
}

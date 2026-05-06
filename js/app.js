const MXTOOLBOX_API_KEY = 'df352fe0-5a8e-4bfb-b3d1-5af56a5b6b48';

// ─── SAMPLE DATA ──────────────────────────────────────────────────────────────
const EXAMPLES = {
  phishing: {
    sender: 'security-alert@paypa1-verify.com',
    subject: 'URGENT: Your PayPal account has been limited!',
    body: `Dear Valued Customer,

We have noticed unusual activity on your PayPal account. Your account access has been LIMITED until we verify your information.

Click the link below IMMEDIATELY to restore your account:
http://paypa1-secure-login.com/verify?token=abc123

If you do not verify within 24 HOURS your account will be PERMANENTLY SUSPENDED.

You must provide:
- Full name
- Social Security Number
- Credit card number and CVV
- Bank account details

This is your FINAL WARNING.

PayPal Security Team`,
    links: 'http://paypa1-secure-login.com/verify?token=abc123\nhttp://bit.ly/paypal-verify-now'
  },
  legit: {
    sender: 'noreply@github.com',
    subject: 'Your pull request was merged',
    body: `Hi there,

Your pull request "Fix authentication bug" (#1234) was merged into main by octocat.

You can view your pull request at: https://github.com/myrepo/pulls/1234

Thanks for contributing!

— The GitHub Team`,
    links: 'https://github.com/myrepo/pulls/1234'
  },
  suspicious: {
    sender: 'hr-department@company-benefits.info',
    subject: 'Action Required: Update your direct deposit info by Friday',
    body: `Hi,

Our payroll system is being updated. All employees must resubmit their direct deposit information by end of week or your next paycheck may be delayed.

Please click below and log in with your company credentials:
https://company-benefits.info/portal/update

If you have questions, do not reply to this email — call HR at extension 5555.

Human Resources`,
    links: 'https://company-benefits.info/portal/update'
  }
};

// ─── HELPERS ──────────────────────────────────────────────────────────────────
function loadExample(key) {
  const e = EXAMPLES[key];
  document.getElementById('sender').value  = e.sender;
  document.getElementById('subject').value = e.subject;
  document.getElementById('body').value    = e.body;
  document.getElementById('links').value   = e.links;
}

function getScoreColor(score) {
  if (score >= 80) return '#a32d2d';
  if (score >= 60) return '#854f0b';
  if (score >= 35) return '#3b6d11';
  return '#0f6e56';
}

function getRiskClass(level) {
  return 'risk-' + level.toLowerCase().replace(/\s+/g, '');
}

function makeFlags(arr, dotClass) {
  return (arr || [])
    .map(f => `<div class="flag-item"><div class="flag-dot ${dotClass}"></div><span>${f}</span></div>`)
    .join('');
}

/**
 * Extracts unique domains from links text + sender email.
 */
function extractDomains(linksText, sender) {
  const domains = new Set();
  const senderMatch = sender.match(/@([\w.-]+)/);
  if (senderMatch) domains.add(senderMatch[1]);
  const urls = linksText.split('\n').filter(Boolean);
  for (const url of urls) {
    try {
      const parsed = new URL(url.trim());
      domains.add(parsed.hostname);
    } catch {}
  }
  return [...domains];
}

// ─── MXTOOLBOX API CHECKS ────────────────────────────────────────────────────

/**
 * Checks a domain against MXToolbox blacklist.
 * Returns { domain, blacklisted, count, listedOn, summary }
 */
async function checkBlacklist(domain) {
  try {
    const res = await fetch(`https://api.mxtoolbox.com/api/v1/lookup/blacklist/${domain}`, {
      headers: { 'Authorization': MXTOOLBOX_API_KEY }
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const failed = data.Failed || [];
    return {
      domain,
      blacklisted: failed.length > 0,
      count: failed.length,
      listedOn: failed.slice(0, 3).map(f => f.Name),
      summary: failed.length > 0
        ? `Blacklisted on ${failed.length} list(s): ${failed.slice(0,3).map(f => f.Name).join(', ')}`
        : 'Clean — not on any blacklists'
    };
  } catch (err) {
    return { domain, blacklisted: false, count: 0, listedOn: [], summary: `Could not check: ${err.message}` };
  }
}

/**
 * Checks MX records for a domain via MXToolbox.
 * Returns { domain, hasMX, mxRecords }
 */
async function checkMXRecord(domain) {
  try {
    const res = await fetch(`https://api.mxtoolbox.com/api/v1/lookup/mx/${domain}`, {
      headers: { 'Authorization': MXTOOLBOX_API_KEY }
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const records = data.Information || [];
    return {
      domain,
      hasMX: records.length > 0,
      mxRecords: records.slice(0,2).map(r => r.Domain || r.Value || '')
    };
  } catch {
    return { domain, hasMX: null, mxRecords: [] };
  }
}

/**
 * Checks SPF record for a domain via MXToolbox.
 * Returns { domain, hasSPF, spfValid }
 */
async function checkSPF(domain) {
  try {
    const res = await fetch(`https://api.mxtoolbox.com/api/v1/lookup/spf/${domain}`, {
      headers: { 'Authorization': MXTOOLBOX_API_KEY }
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const failed = (data.Failed || []).length;
    const passed = (data.Passed || []).length;
    return {
      domain,
      hasSPF: passed > 0 || failed > 0,
      spfValid: failed === 0 && passed > 0
    };
  } catch {
    return { domain, hasSPF: null, spfValid: null };
  }
}

// ─── RULE-BASED SCORING ENGINE ────────────────────────────────────────────────

const URGENCY_WORDS = [
  'urgent', 'immediately', 'final warning', 'act now', 'expire', 'suspended',
  'limited', 'verify now', 'within 24 hours', 'account locked', 'unusual activity',
  'permanently', 'last chance', 'action required', 'confirm now', 'alert'
];

const SENSITIVE_KEYWORDS = [
  'social security', 'ssn', 'credit card', 'cvv', 'bank account', 'password',
  'date of birth', 'mother\'s maiden', 'pin number', 'full name and address',
  'direct deposit', 'routing number', 'wire transfer'
];

const LOOKALIKE_BRANDS = [
  { brand: 'paypal', patterns: ['paypa1', 'pay-pal', 'paypa1', 'paypel', 'pypal'] },
  { brand: 'amazon', patterns: ['amaz0n', 'arnazon', 'amazon-secure', 'amazon-login'] },
  { brand: 'google', patterns: ['g00gle', 'googIe', 'google-verify', 'gooogle'] },
  { brand: 'microsoft', patterns: ['micros0ft', 'microsofft', 'microsoft-secure'] },
  { brand: 'apple', patterns: ['app1e', 'apple-id', 'applesuport'] },
  { brand: 'netflix', patterns: ['netf1ix', 'netflox', 'net-flix'] },
  { brand: 'bank', patterns: ['bank-secure', 'bankverify', 'bank-login'] },
];

const SUSPICIOUS_TLDS = ['.xyz', '.top', '.click', '.loan', '.gq', '.ml', '.cf', '.tk', '.pw', '.info'];
const URL_SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.link', 'rebrand.ly', 'is.gd'];
const FREE_EMAIL_PROVIDERS = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'protonmail.com'];

/**
 * Core rule-based phishing analysis engine.
 * Returns { score, redFlags, warnings, positiveSignals }
 */
function runRuleEngine(sender, subject, body, links, mxtoolboxResults) {
  let score = 0;
  const redFlags = [];
  const warnings = [];
  const positiveSignals = [];

  const bodyLower    = body.toLowerCase();
  const subjectLower = subject.toLowerCase();
  const senderLower  = sender.toLowerCase();
  const allText      = `${bodyLower} ${subjectLower} ${senderLower}`;
  const linksArr     = links.split('\n').map(l => l.trim()).filter(Boolean);

  // ── MXTOOLBOX RESULTS ──────────────────────────────────────────────────────
  const { blacklistResults, mxResults, spfResults } = mxtoolboxResults;

  for (const bl of blacklistResults) {
    if (bl.blacklisted) {
      score += Math.min(40, bl.count * 8);
      redFlags.push(`Domain "${bl.domain}" is blacklisted on ${bl.count} list(s): ${bl.listedOn.join(', ')}`);
    } else {
      positiveSignals.push(`Domain "${bl.domain}" is clean — not on any blacklists`);
    }
  }

  for (const mx of mxResults) {
    if (mx.hasMX === false) {
      score += 10;
      warnings.push(`Domain "${mx.domain}" has no MX records — unusual for a legitimate sender`);
    } else if (mx.hasMX && mx.mxRecords.length > 0) {
      positiveSignals.push(`Domain "${mx.domain}" has valid MX records`);
    }
  }

  for (const spf of spfResults) {
    if (spf.hasSPF === false) {
      score += 8;
      warnings.push(`Domain "${spf.domain}" has no SPF record — email authentication not configured`);
    } else if (spf.spfValid) {
      positiveSignals.push(`Domain "${spf.domain}" has a valid SPF record`);
    } else if (spf.spfValid === false) {
      score += 12;
      redFlags.push(`Domain "${spf.domain}" has a failing SPF record`);
    }
  }

  // ── SENDER CHECKS ──────────────────────────────────────────────────────────
  const senderDomainMatch = sender.match(/@([\w.-]+)/);
  const senderDomain = senderDomainMatch ? senderDomainMatch[1] : '';

  // Free email provider used for business impersonation
  if (FREE_EMAIL_PROVIDERS.includes(senderDomain)) {
    const impersonatesCompany = LOOKALIKE_BRANDS.some(b => allText.includes(b.brand));
    if (impersonatesCompany) {
      score += 20;
      redFlags.push(`Sender uses free email (${senderDomain}) but appears to impersonate a company`);
    } else {
      warnings.push(`Sender is using a free email provider (${senderDomain})`);
      score += 5;
    }
  }

  // Lookalike domain check
  for (const { brand, patterns } of LOOKALIKE_BRANDS) {
    if (patterns.some(p => senderDomain.includes(p))) {
      score += 30;
      redFlags.push(`Sender domain appears to be a lookalike of "${brand}" — likely spoofed`);
    }
  }

  // Suspicious TLD in sender
  if (SUSPICIOUS_TLDS.some(tld => senderDomain.endsWith(tld))) {
    score += 15;
    warnings.push(`Sender domain uses a suspicious TLD (${senderDomain})`);
  }

  // Subdomain spoofing (e.g. paypal.evil.com)
  for (const { brand } of LOOKALIKE_BRANDS) {
    if (senderDomain.includes(brand) && !senderDomain.endsWith(`.${brand}.com`) && senderDomain !== `${brand}.com`) {
      score += 20;
      redFlags.push(`Sender domain "${senderDomain}" contains "${brand}" but is not the real domain — possible subdomain spoofing`);
    }
  }

  // Excessive subdomains
  if ((senderDomain.match(/\./g) || []).length >= 3) {
    score += 10;
    warnings.push(`Sender domain has an unusual number of subdomains: ${senderDomain}`);
  }

  // Hyphens in domain (common in phishing)
  if ((senderDomain.match(/-/g) || []).length >= 2) {
    score += 8;
    warnings.push(`Sender domain contains multiple hyphens — common in phishing domains`);
  }

  // ── SUBJECT CHECKS ────────────────────────────────────────────────────────
  const urgencyInSubject = URGENCY_WORDS.filter(w => subjectLower.includes(w));
  if (urgencyInSubject.length >= 2) {
    score += 15;
    redFlags.push(`Subject line uses multiple urgency tactics: "${urgencyInSubject.slice(0,3).join('", "')}"`);
  } else if (urgencyInSubject.length === 1) {
    score += 7;
    warnings.push(`Subject line uses urgency language: "${urgencyInSubject[0]}"`);
  }

  // All caps words in subject
  const capsWords = (subject.match(/\b[A-Z]{3,}\b/g) || []);
  if (capsWords.length >= 2) {
    score += 8;
    warnings.push(`Subject uses excessive capitalization: ${capsWords.slice(0,3).join(', ')}`);
  }

  // ── BODY CHECKS ───────────────────────────────────────────────────────────

  // Requests for sensitive info
  const sensitiveFound = SENSITIVE_KEYWORDS.filter(k => bodyLower.includes(k));
  if (sensitiveFound.length > 0) {
    score += Math.min(35, sensitiveFound.length * 12);
    redFlags.push(`Email requests sensitive information: ${sensitiveFound.slice(0,4).join(', ')}`);
  }

  // Urgency in body
  const urgencyInBody = URGENCY_WORDS.filter(w => bodyLower.includes(w));
  if (urgencyInBody.length >= 3) {
    score += 12;
    redFlags.push(`Body uses heavy urgency/pressure tactics (${urgencyInBody.length} urgency phrases detected)`);
  } else if (urgencyInBody.length >= 1) {
    score += 5;
    warnings.push(`Body contains urgency language: "${urgencyInBody.slice(0,2).join('", "')}"`);
  }

  // Generic greeting (Dear Customer vs name)
  if (bodyLower.includes('dear customer') || bodyLower.includes('dear valued') || bodyLower.includes('dear user')) {
    score += 8;
    warnings.push('Generic greeting ("Dear Customer/Valued Customer") instead of a real name');
  }

  // Threats of account suspension
  if (bodyLower.includes('suspend') || bodyLower.includes('terminate') || bodyLower.includes('permanently closed')) {
    score += 10;
    warnings.push('Email threatens account suspension or termination');
  }

  // Grammar/spelling issues (simple heuristic — very long run-on sentences)
  const sentences = body.split(/[.!?]+/).filter(s => s.trim().length > 0);
  const avgLength = sentences.reduce((a, s) => a + s.split(' ').length, 0) / (sentences.length || 1);
  if (avgLength > 40) {
    score += 5;
    warnings.push('Email contains unusually long sentences — possible grammar issues');
  }

  // ── LINK CHECKS ───────────────────────────────────────────────────────────
  for (const link of linksArr) {
    let linkDomain = '';
    try { linkDomain = new URL(link).hostname; } catch {}

    // HTTP (not HTTPS)
    if (link.startsWith('http://')) {
      score += 12;
      redFlags.push(`Link uses insecure HTTP (not HTTPS): ${link}`);
    }

    // URL shorteners
    if (URL_SHORTENERS.some(s => linkDomain.includes(s))) {
      score += 15;
      warnings.push(`Link uses a URL shortener (${linkDomain}) — destination is hidden`);
    }

    // Suspicious TLD in link
    if (SUSPICIOUS_TLDS.some(tld => linkDomain.endsWith(tld))) {
      score += 12;
      warnings.push(`Link domain uses a suspicious TLD: ${linkDomain}`);
    }

    // Lookalike domain in links
    for (const { brand, patterns } of LOOKALIKE_BRANDS) {
      if (patterns.some(p => linkDomain.includes(p))) {
        score += 25;
        redFlags.push(`Link points to a lookalike domain spoofing "${brand}": ${linkDomain}`);
      }
    }

    // Mismatched brand (email says PayPal but link goes elsewhere)
    for (const { brand } of LOOKALIKE_BRANDS) {
      if (allText.includes(brand) && !linkDomain.includes(brand) && linkDomain !== `${brand}.com`) {
        // only warn if domain looks unrelated
        if (!linkDomain.includes('github') && !linkDomain.includes('google')) {
          score += 8;
          warnings.push(`Email mentions "${brand}" but link goes to a different domain: ${linkDomain}`);
          break;
        }
      }
    }

    // Suspicious query parameters
    if (link.includes('token=') || link.includes('verify=') || link.includes('confirm=')) {
      score += 6;
      warnings.push(`Link contains tracking/verification token parameters: ${link.substring(0, 60)}...`);
    }
  }

  // Positive signals for legitimate emails
  if (linksArr.every(l => l.startsWith('https://'))) {
    positiveSignals.push('All links use secure HTTPS');
  }
  if (!linksArr.some(l => URL_SHORTENERS.some(s => l.includes(s)))) {
    positiveSignals.push('No URL shorteners used — link destinations are transparent');
  }
  if (sensitiveFound.length === 0) {
    positiveSignals.push('Email does not request sensitive personal information');
  }
  if (urgencyInSubject.length === 0 && urgencyInBody.length === 0) {
    positiveSignals.push('No urgency tactics or pressure language detected');
  }

  // ── FINAL SCORE ────────────────────────────────────────────────────────────
  score = Math.min(100, Math.max(0, score));

  let riskLevel;
  if (score >= 80) riskLevel = 'Critical';
  else if (score >= 60) riskLevel = 'High';
  else if (score >= 35) riskLevel = 'Medium';
  else if (score >= 15) riskLevel = 'Low';
  else riskLevel = 'Safe';

  return { score, riskLevel, redFlags, warnings, positiveSignals };
}

// ─── SUMMARY GENERATOR ────────────────────────────────────────────────────────

function generateSummary(score, riskLevel, redFlags, warnings, positiveSignals, sender) {
  const senderDomain = (sender.match(/@([\w.-]+)/) || [])[1] || 'unknown domain';
  const blacklisted = redFlags.some(f => f.toLowerCase().includes('blacklisted'));

  if (score >= 80) {
    return `This email shows strong indicators of a phishing attack. ${
      blacklisted ? `The sender domain "${senderDomain}" is actively blacklisted. ` : ''
    }${redFlags.length} serious red flags were detected including ${
      redFlags.slice(0,2).join(' and ').toLowerCase()
    }. Do not interact with this email.`;
  }
  if (score >= 60) {
    return `This email has several concerning signals that suggest it may be a phishing attempt. ${
      redFlags.length > 0 ? `Key concerns include: ${redFlags[0].toLowerCase()}. ` : ''
    }Exercise extreme caution before clicking any links or responding.`;
  }
  if (score >= 35) {
    return `This email has some suspicious characteristics worth noting. ${
      warnings.length > 0 ? `Caution signals include: ${warnings[0].toLowerCase()}. ` : ''
    }While not definitively phishing, verify the sender through a separate channel before taking action.`;
  }
  return `This email appears to be legitimate. ${
    positiveSignals.length > 0 ? `Positive signals include: ${positiveSignals[0].toLowerCase()}. ` : ''
  }No major phishing indicators were detected, though always remain cautious with unexpected emails.`;
}

function generateRecommendation(score, riskLevel) {
  if (score >= 80) return '🚫 Do NOT click any links or download attachments. Mark as phishing/spam and delete immediately. If this email appears to be from a company you use, contact that company directly through their official website to check your account status.';
  if (score >= 60) return '⚠️ Treat this email with extreme suspicion. Do not click links or provide any information. If you believe it might be legitimate, navigate to the sender\'s official website directly (type it in your browser) and log in to check for any real notifications.';
  if (score >= 35) return '🔶 Proceed with caution. Verify the sender\'s identity through a separate communication channel before clicking any links or taking action. Do not provide sensitive information via email.';
  return '✅ This email appears safe, but always stay vigilant. If something feels off, trust your instincts and verify through official channels.';
}

// ─── RENDER RESULT ────────────────────────────────────────────────────────────

function renderResult(data, mxtoolboxDetails) {
  const score     = data.riskScore  || 0;
  const level     = data.riskLevel  || 'Unknown';
  const riskClass = getRiskClass(level);
  const icon      = score >= 75 ? 'ti-alert-triangle' : score >= 45 ? 'ti-alert-circle' : 'ti-circle-check';
  const subtitle  = score >= 75 ? '— Likely Phishing' : score >= 45 ? '— Use Caution' : '— Appears Safe';

  // Build MXToolbox details section
  const mxSection = mxtoolboxDetails.length > 0 ? `
    <div class="section-title"><i class="ti ti-database" style="font-size:14px;vertical-align:-1px;margin-right:4px"></i>MXToolbox live checks</div>
    <div class="flag-list">
      ${mxtoolboxDetails.map(d => `
        <div class="flag-item">
          <div class="flag-dot ${d.ok ? 'dot-success' : 'dot-warning'}"></div>
          <span>${d.text}</span>
        </div>`).join('')}
    </div>` : '';

  return `
  <div class="result-card">
    <div class="risk-banner ${riskClass}">
      <i class="ti ${icon}"></i>
      <div>
        <div class="risk-label">${level} Risk ${subtitle}</div>
        <div class="risk-sublabel">Phishing confidence score: ${score}/100</div>
      </div>
    </div>

    <div class="score-bar-wrap">
      <div class="score-row">
        <span class="score-num">${score}<span class="score-denom">/100</span></span>
        <span class="score-tag">Risk score</span>
      </div>
      <div class="score-bar-bg">
        <div class="score-bar-fill" style="width:${score}%; background:${getScoreColor(score)};"></div>
      </div>
    </div>

    <hr class="divider">

    <div class="analysis-body">
      ${data.redFlags?.length
        ? `<div class="section-title"><i class="ti ti-alert-triangle" style="font-size:14px;vertical-align:-1px;margin-right:4px"></i>Red flags detected</div>
           <div class="flag-list">${makeFlags(data.redFlags, 'dot-danger')}</div>`
        : ''}

      ${data.warnings?.length
        ? `<div class="section-title"><i class="ti ti-alert-circle" style="font-size:14px;vertical-align:-1px;margin-right:4px"></i>Caution signals</div>
           <div class="flag-list">${makeFlags(data.warnings, 'dot-warning')}</div>`
        : ''}

      ${data.positiveSignals?.length
        ? `<div class="section-title"><i class="ti ti-circle-check" style="font-size:14px;vertical-align:-1px;margin-right:4px"></i>Positive signals</div>
           <div class="flag-list">${makeFlags(data.positiveSignals, 'dot-success')}</div>`
        : ''}

      ${mxSection}

      <div class="section-title"><i class="ti ti-file-text" style="font-size:14px;vertical-align:-1px;margin-right:4px"></i>Summary</div>
      <p class="summary-text">${data.summary || ''}</p>

      <div class="section-title"><i class="ti ti-bulb" style="font-size:14px;vertical-align:-1px;margin-right:4px"></i>Recommended action</div>
      <div class="rec-box">${data.recommendation || ''}</div>
    </div>
  </div>`;
}

// ─── MAIN ANALYSIS FUNCTION ───────────────────────────────────────────────────

async function analyze() {
  const sender  = document.getElementById('sender').value.trim();
  const subject = document.getElementById('subject').value.trim();
  const body    = document.getElementById('body').value.trim();
  const links   = document.getElementById('links').value.trim();

  if (!body && !sender && !subject) {
    alert('Please enter at least the sender, subject, or email body.');
    return;
  }

  const btn       = document.getElementById('analyzeBtn');
  const resultDiv = document.getElementById('result');

  btn.disabled  = true;
  btn.innerHTML = '<div class="spinner"></div> Checking domains with MXToolbox...';
  resultDiv.innerHTML = '';

  // ── Step 1: MXToolbox live checks ────────────────────────────────────────
  const domains = extractDomains(links, sender);
  let blacklistResults = [], mxResults = [], spfResults = [];

  if (domains.length > 0) {
    // Run all checks in parallel
    [blacklistResults, mxResults, spfResults] = await Promise.all([
      Promise.all(domains.map(checkBlacklist)),
      Promise.all(domains.map(checkMXRecord)),
      Promise.all(domains.map(checkSPF))
    ]);
  }

  btn.innerHTML = '<div class="spinner"></div> Running phishing analysis...';

  // ── Step 2: Rule-based scoring ────────────────────────────────────────────
  const { score, riskLevel, redFlags, warnings, positiveSignals } = runRuleEngine(
    sender, subject, body, links,
    { blacklistResults, mxResults, spfResults }
  );

  const summary        = generateSummary(score, riskLevel, redFlags, warnings, positiveSignals, sender);
  const recommendation = generateRecommendation(score, riskLevel);

  // ── Step 3: Build MXToolbox details for display ───────────────────────────
  const mxtoolboxDetails = [];
  for (const bl of blacklistResults) {
    mxtoolboxDetails.push({ ok: !bl.blacklisted, text: `Blacklist check — ${bl.summary}` });
  }
  for (const mx of mxResults) {
    if (mx.hasMX !== null) {
      mxtoolboxDetails.push({
        ok: mx.hasMX,
        text: `MX records — ${mx.domain}: ${mx.hasMX ? `Valid (${mx.mxRecords.join(', ')})` : 'No MX records found'}`
      });
    }
  }
  for (const spf of spfResults) {
    if (spf.hasSPF !== null) {
      mxtoolboxDetails.push({
        ok: spf.spfValid,
        text: `SPF record — ${spf.domain}: ${spf.spfValid ? 'Valid SPF' : spf.hasSPF ? 'SPF present but failing' : 'No SPF record'}`
      });
    }
  }

  // ── Step 4: Render ────────────────────────────────────────────────────────
  resultDiv.innerHTML = renderResult({
    riskScore: score,
    riskLevel,
    redFlags,
    warnings,
    positiveSignals,
    summary,
    recommendation
  }, mxtoolboxDetails);

  btn.disabled  = false;
  btn.innerHTML = '<i class="ti ti-radar"></i> Analyze for phishing ↗';
}
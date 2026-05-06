
const API_KEY = 'df352fe0-5a8e-4bfb-b3d1-5af56a5b6b48';


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

/**
 * Fills the form inputs with a pre-built example email.
 * @param {'phishing'|'legit'|'suspicious'} key
 */
function loadExample(key) {
  const e = EXAMPLES[key];
  document.getElementById('sender').value  = e.sender;
  document.getElementById('subject').value = e.subject;
  document.getElementById('body').value    = e.body;
  document.getElementById('links').value   = e.links;
}

/**
 * Returns a hex color for the score bar based on risk level.
 * @param {number} score  0–100
 * @returns {string}
 */
function getScoreColor(score) {
  if (score >= 80) return '#a32d2d'; // critical / red
  if (score >= 60) return '#854f0b'; // high    / amber
  if (score >= 35) return '#3b6d11'; // medium  / green
  return '#0f6e56';                  // safe    / teal
}

/**
 * Converts a risk level string into the matching CSS class name.
 * @param {string} level  e.g. "Critical", "High", "Medium", "Low", "Safe"
 * @returns {string}
 */
function getRiskClass(level) {
  return 'risk-' + level.toLowerCase().replace(/\s+/g, '');
}

/**
 * Builds the HTML for a list of flag items.
 * @param {string[]} arr       Flag texts
 * @param {string}   dotClass  CSS class for the coloured dot
 * @returns {string}
 */
function makeFlags(arr, dotClass) {
  return (arr || [])
    .map(f => `<div class="flag-item"><div class="flag-dot ${dotClass}"></div><span>${f}</span></div>`)
    .join('');
}


// ─── RENDER RESULT ────────────────────────────────────────────────────────────

/**
 * Converts the parsed API response into an HTML result card.
 * @param {object} data  Parsed JSON from the Claude API
 * @returns {string}     HTML string
 */
function renderResult(data) {
  const score    = data.riskScore  || 0;
  const level    = data.riskLevel  || 'Unknown';
  const riskClass = getRiskClass(level);
  const icon     = score >= 75 ? 'ti-alert-triangle' : score >= 45 ? 'ti-alert-circle' : 'ti-circle-check';
  const subtitle = score >= 75 ? '— Likely Phishing'  : score >= 45 ? '— Use Caution'   : '— Appears Safe';

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

      <div class="section-title"><i class="ti ti-file-text" style="font-size:14px;vertical-align:-1px;margin-right:4px"></i>Summary</div>
      <p class="summary-text">${data.summary || ''}</p>

      <div class="section-title"><i class="ti ti-bulb" style="font-size:14px;vertical-align:-1px;margin-right:4px"></i>Recommended action</div>
      <div class="rec-box">${data.recommendation || ''}</div>
    </div>
  </div>`;
}


// ─── MAIN ANALYSIS FUNCTION ───────────────────────────────────────────────────

/**
 * Reads the form, calls the Claude API, and renders the result.
 */
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

  // Loading state
  btn.disabled   = true;
  btn.innerHTML  = '<div class="spinner"></div> Analyzing...';
  resultDiv.innerHTML = '';

  // Build the prompt sent to Claude
  const prompt = `You are a cybersecurity expert specializing in phishing detection. Analyze this email for phishing indicators and return ONLY a valid JSON object (no markdown, no backticks, no commentary).

Email to analyze:
- Sender: ${sender  || 'not provided'}
- Subject: ${subject || 'not provided'}
- Body: ${body    || 'not provided'}
- Links found: ${links   || 'none'}

Return this exact JSON structure:
{
  "riskScore": <integer 0-100 where 0=definitely safe, 100=definite phishing>,
  "riskLevel": <"Critical" | "High" | "Medium" | "Low" | "Safe">,
  "redFlags": [<list of serious phishing indicators found, be specific>],
  "warnings": [<list of moderately suspicious things that are not definitive>],
  "positiveSignals": [<list of things that suggest legitimacy>],
  "summary": "<2-3 sentence plain English summary of the analysis>",
  "recommendation": "<one clear actionable recommendation for what to do with this email>"
}

Be thorough: check for lookalike domains, urgency tactics, suspicious links, grammar, requests for sensitive info, mismatched branding, SPF/DKIM hints, etc.`;

  try {
    const response = await fetch('http://data.phishtank.com/data/<your app key>/online-valid.json.bz2', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': API_KEY,                             // required for local use
        'anthropic-version': '2023-06-01',
        'anthropic-dangerous-direct-browser-access': 'true'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 1000,
        messages: [{ role: 'user', content: prompt }]
      })
    });

    const data  = await response.json();
    const text  = data.content.map(i => i.text || '').join('');
    const clean = text.replace(/```json|```/g, '').trim();
    const parsed = JSON.parse(clean);

    resultDiv.innerHTML = renderResult(parsed);

  } catch (err) {
    resultDiv.innerHTML = `<div class="error-box">Analysis failed: ${err.message}. Check your API key and try again.</div>`;
  }

  // Reset button
  btn.disabled  = false;
  btn.innerHTML = '<i class="ti ti-radar"></i> Analyze for phishing ↗';
}
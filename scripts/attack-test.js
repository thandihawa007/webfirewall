/**
 * Droplet Attack Test Suite
 * Sends sample payloads (SQLi, XSS, Path Traversal, Bad User Agent, Flood)
 * to a protected Droplet URL and reports inspection results.
 *
 * Usage:
 *   node scripts/attack-test.js [target_url]
 * Example:
 *   node scripts/attack-test.js http://localhost:3000/p/1/
 */

const http = require('http');
const https = require('https');
const { URL } = require('url');

const targetUrlStr = process.argv[2] || 'http://localhost:3000/p/1/';
console.log(`\n========================================================`);
console.log(` 🛡️  DROPLET WAF & PROXY SECURITY AUDIT SUITE`);
console.log(` Target Protected Endpoint: ${targetUrlStr}`);
console.log(`========================================================\n`);

function sendRequest(urlStr, options = {}) {
  return new Promise((resolve) => {
    let parsed;
    try {
      parsed = new URL(urlStr);
    } catch (e) {
      return resolve({ error: 'Invalid URL: ' + e.message, status: 0 });
    }

    const client = parsed.protocol === 'https:' ? https : http;
    const reqOptions = {
      protocol: parsed.protocol,
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: options.method || 'GET',
      headers: {
        'User-Agent': options.userAgent || 'DropletAuditAgent/1.0',
        ...(options.headers || {})
      },
      timeout: 5000
    };

    const req = client.request(reqOptions, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        resolve({
          status: res.statusCode,
          headers: res.headers,
          body
        });
      });
    });

    req.on('error', (err) => {
      resolve({ error: err.message, status: 0 });
    });

    req.on('timeout', () => {
      req.destroy();
      resolve({ error: 'Request timed out', status: 0 });
    });

    if (options.body) {
      req.write(typeof options.body === 'string' ? options.body : JSON.stringify(options.body));
    }
    req.end();
  });
}

async function runAudit() {
  const base = targetUrlStr.replace(/\/+$/, '');
  const results = [];

  // 1. Clean Baseline Request
  process.stdout.write('[1/6] Sending Baseline Clean Request... ');
  const resClean = await sendRequest(`${base}/health`);
  const cleanOk = resClean.status !== 403;
  results.push({
    test: 'Clean Traffic',
    payload: '/health (benign)',
    status: resClean.status,
    blocked: !cleanOk,
    expected: 'ALLOWED',
    pass: cleanOk
  });
  console.log(`Status: ${resClean.status} -> ${cleanOk ? 'ALLOWED (Pass)' : 'BLOCKED (Check target)'}`);

  // 2. SQL Injection (SQLi)
  process.stdout.write('[2/6] Testing SQL Injection (\' OR 1=1 --)... ');
  const sqliUrl = `${base}/search?q=` + encodeURIComponent("' OR 1=1 --");
  const resSqli = await sendRequest(sqliUrl);
  const sqliBlocked = resSqli.status === 403;
  results.push({
    test: 'SQL Injection (SQLi)',
    payload: '\' OR 1=1 --',
    status: resSqli.status,
    blocked: sqliBlocked,
    expected: 'BLOCKED (403)',
    pass: sqliBlocked
  });
  console.log(`Status: ${resSqli.status} -> ${sqliBlocked ? 'BLOCKED (Pass)' : 'MISSED (Fail)'}`);

  // 3. Cross-Site Scripting (XSS)
  process.stdout.write('[3/6] Testing Cross-Site Scripting (<script> tag)... ');
  const xssUrl = `${base}/comment?text=` + encodeURIComponent('<script>alert("XSS")</script>');
  const resXss = await sendRequest(xssUrl);
  const xssBlocked = resXss.status === 403;
  results.push({
    test: 'Cross-Site Scripting (XSS)',
    payload: '<script>alert("XSS")</script>',
    status: resXss.status,
    blocked: xssBlocked,
    expected: 'BLOCKED (403)',
    pass: xssBlocked
  });
  console.log(`Status: ${resXss.status} -> ${xssBlocked ? 'BLOCKED (Pass)' : 'MISSED (Fail)'}`);

  // 4. Path Traversal
  process.stdout.write('[4/6] Testing Path Traversal (../../etc/passwd)... ');
  const traversalUrl = `${base}/files?path=` + encodeURIComponent('../../../../etc/passwd');
  const resTraversal = await sendRequest(traversalUrl);
  const traversalBlocked = resTraversal.status === 403;
  results.push({
    test: 'Path Traversal',
    payload: '../../../../etc/passwd',
    status: resTraversal.status,
    blocked: traversalBlocked,
    expected: 'BLOCKED (403)',
    pass: traversalBlocked
  });
  console.log(`Status: ${resTraversal.status} -> ${traversalBlocked ? 'BLOCKED (Pass)' : 'MISSED (Fail)'}`);

  // 5. Malicious Scanner User-Agent (Bot Detection)
  process.stdout.write('[5/10] Testing Malicious Scanner Bot User-Agent (sqlmap)... ');
  const resBot = await sendRequest(`${base}/api/data`, {
    userAgent: 'sqlmap/1.5.2#stable (http://sqlmap.org)'
  });
  const botBlocked = resBot.status === 403;
  results.push({
    test: 'Malicious Scanner Bot',
    payload: 'sqlmap/1.5.2 User-Agent',
    status: resBot.status,
    blocked: botBlocked,
    expected: 'BLOCKED (403)',
    pass: botBlocked
  });
  console.log(`Status: ${resBot.status} -> ${botBlocked ? 'BLOCKED (Pass)' : 'MISSED (Fail)'}`);

  // 6. SQLi Comment Obfuscation (Evasion)
  process.stdout.write('[6/10] Testing Obfuscated SQLi (UN/**/ION SEL/**/ECT)... ');
  const sqliObfUrl = `${base}/items?category=` + encodeURIComponent('1 UN/**/ION SEL/**/ECT 1,2,3--');
  const resSqliObf = await sendRequest(sqliObfUrl);
  const sqliObfBlocked = resSqliObf.status === 403;
  results.push({
    test: 'SQLi Comment Obfuscation',
    payload: '1 UN/**/ION SEL/**/ECT 1,2,3--',
    status: resSqliObf.status,
    blocked: sqliObfBlocked,
    expected: 'BLOCKED (403)',
    pass: sqliObfBlocked
  });
  console.log(`Status: ${resSqliObf.status} -> ${sqliObfBlocked ? 'BLOCKED (Pass)' : 'MISSED (Fail)'}`);

  // 7. XSS SVG Onload (Evasion)
  process.stdout.write('[7/10] Testing SVG Event Handler XSS (<svg onload=alert(1)>)... ');
  const xssSvgUrl = `${base}/profile?name=` + encodeURIComponent('<svg onload=alert(1)>');
  const resXssSvg = await sendRequest(xssSvgUrl);
  const xssSvgBlocked = resXssSvg.status === 403;
  results.push({
    test: 'XSS SVG Onload',
    payload: '<svg onload=alert(1)>',
    status: resXssSvg.status,
    blocked: xssSvgBlocked,
    expected: 'BLOCKED (403)',
    pass: xssSvgBlocked
  });
  console.log(`Status: ${resXssSvg.status} -> ${xssSvgBlocked ? 'BLOCKED (Pass)' : 'MISSED (Fail)'}`);

  // 8. Double-Encoded Path Traversal (Evasion)
  process.stdout.write('[8/10] Testing Double-Encoded Traversal (%252e%252e%252f)... ');
  const resDoubleTrav = await sendRequest(`${base}/download?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd`);
  const doubleTravBlocked = resDoubleTrav.status === 403;
  results.push({
    test: 'Double-Encoded Traversal',
    payload: '%252e%252e%252f%252e%252e%252fetc%252fpasswd',
    status: resDoubleTrav.status,
    blocked: doubleTravBlocked,
    expected: 'BLOCKED (403)',
    pass: doubleTravBlocked
  });
  console.log(`Status: ${resDoubleTrav.status} -> ${doubleTravBlocked ? 'BLOCKED (Pass)' : 'MISSED (Fail)'}`);

  // 9. Oversized Body (>10KB limit)
  process.stdout.write('[9/10] Testing Oversized Body (>10KB)... ');
  const oversizedPayload = { data: 'A'.repeat(12 * 1024) }; // 12KB
  const resOversized = await sendRequest(`${base}/api/upload`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: oversizedPayload
  });
  const oversizedBlocked = resOversized.status === 403;
  results.push({
    test: 'Oversized Body (>10KB)',
    payload: '12KB JSON payload',
    status: resOversized.status,
    blocked: oversizedBlocked,
    expected: 'BLOCKED (403)',
    pass: oversizedBlocked
  });
  console.log(`Status: ${resOversized.status} -> ${oversizedBlocked ? 'BLOCKED (Pass)' : 'MISSED (Fail)'}`);

  // 10. Request Flood / DDoS (> 100 req/min per IP threshold)
  process.stdout.write('[10/10] Testing Rapid Flood (sending 105 requests for DDoS threshold)... ');
  let ddosBlocked = false;
  let finalStatus = 200;

  for (let i = 0; i < 105; i++) {
    const res = await sendRequest(`${base}/ping?seq=${i}`);
    finalStatus = res.status;
    if (res.status === 403) {
      ddosBlocked = true;
      break;
    }
  }
  results.push({
    test: 'Flood / Rate Limit (DDoS)',
    payload: '105 rapid requests (>100 limit)',
    status: finalStatus,
    blocked: ddosBlocked,
    expected: 'BLOCKED (403)',
    pass: ddosBlocked
  });
  console.log(`Status: ${finalStatus} -> ${ddosBlocked ? 'BLOCKED (Pass)' : 'THRESHOLD NOT REACHED'}`);

  // Summary Table
  console.log('\n========================================================');
  console.log('                 TEST RESULTS SUMMARY');
  console.log('========================================================');
  console.table(results.map(r => ({
    'Test Name': r.test,
    'Status': r.status,
    'Expected': r.expected,
    'Blocked?': r.blocked ? 'YES' : 'NO',
    'Verdict': r.pass ? 'PASS ✅' : 'FAIL ❌'
  })));

  const allPassed = results.every(r => r.pass);
  if (allPassed) {
    console.log('\n🎉 ALL SECURITY AUDIT TESTS PASSED!\n');
  } else {
    console.log('\n⚠️ SOME TESTS DID NOT PASS. Verify target site mode and routing.\n');
  }
}

runAudit();

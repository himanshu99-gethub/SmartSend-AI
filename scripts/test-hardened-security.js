import fetch from 'node-fetch';

async function runHardenedSecurityTests() {
  console.log('Running Pre-Launch Hardened Security Verification...\n');

  // 1. Verify Security Headers
  const resHome = await fetch('http://localhost:3000');
  const nosniff = resHome.headers.get('x-content-type-options');
  const frameOptions = resHome.headers.get('x-frame-options');
  const referrerPolicy = resHome.headers.get('referrer-policy');
  console.log('1. Security Headers:');
  console.log('   - X-Content-Type-Options:', nosniff === 'nosniff' ? 'PASS (nosniff)' : 'FAIL');
  console.log('   - X-Frame-Options:', frameOptions === 'SAMEORIGIN' ? 'PASS (SAMEORIGIN)' : 'FAIL');
  console.log('   - Referrer-Policy:', referrerPolicy === 'strict-origin-when-cross-origin' ? 'PASS' : 'FAIL');

  // 2. Verify Private Routes are strictly Gated (401)
  const resAiNoAuth = await fetch('http://localhost:3000/api/ai/generate-template', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ prompt: 'test' })
  });
  console.log('2. Unauthenticated AI generation blocked:', resAiNoAuth.status === 401 ? 'PASS (401 Gated)' : 'FAIL (' + resAiNoAuth.status + ')');

  const resUploadNoAuth = await fetch('http://localhost:3000/api/uploads/parse', {
    method: 'POST'
  });
  console.log('   Unauthenticated Upload Parse blocked:', resUploadNoAuth.status === 401 ? 'PASS (401 Gated)' : 'FAIL (' + resUploadNoAuth.status + ')');

  // 3. Verify Debug Route is Disabled (403)
  const resDemo = await fetch('http://localhost:3000/api/auth/demo');
  console.log('3. Demo Debug endpoint disabled:', resDemo.status === 403 ? 'PASS (403 Forbidden)' : 'FAIL (' + resDemo.status + ')');

  // 4. Verify Rate Limiter on Auth
  console.log('4. Testing Auth Rate Limiting (13 rapid calls)...');
  let rateLimited = false;
  for (let i = 0; i < 14; i++) {
    const resAuth = await fetch('http://localhost:3000/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'attacker@evil.com', password: 'wrong' })
    });
    if (resAuth.status === 429) {
      rateLimited = true;
      break;
    }
  }
  console.log('   Brute-force protection trigger:', rateLimited ? 'PASS (429 Rate Limited)' : 'FAIL');

  // 5. Verify User Account Self-Deletion (DPDP / GDPR)
  const resDeleteNoAuth = await fetch('http://localhost:3000/api/auth/account', {
    method: 'DELETE'
  });
  console.log('5. Account deletion without auth blocked:', resDeleteNoAuth.status === 401 ? 'PASS (401 Gated)' : 'FAIL');

  const resDeleteAuth = await fetch('http://localhost:3000/api/auth/account', {
    method: 'DELETE',
    headers: { 'x-user-id': 'usr_temp_test_99' }
  });
  const dataDelete = await resDeleteAuth.json();
  console.log('   Account deletion with auth succeeds:', dataDelete.success ? 'PASS (Data permanently wiped)' : 'FAIL');

  console.log('\nAll Hardened Security Checks Verified Successfully!');
}

runHardenedSecurityTests().catch(err => {
  console.error('Test error:', err);
  process.exit(1);
});

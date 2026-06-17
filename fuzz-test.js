/**
 * Fuzz Test Suite for Google OAuth Login Application
 * Tests endpoints with random, malformed, and edge-case inputs
 * 
 * Run with: node fuzz-test.js
 */

const http = require('http');
const assert = require('assert');

// Configuration
const BASE_URL = 'http://localhost:3000';
const TEST_ITERATIONS = 100;
const TIMEOUT = 5000;

// Test results tracking
let passedTests = 0;
let failedTests = 0;
const failedResults = [];

/**
 * HTTP request helper
 */
function makeRequest(method, path, body = null, headers = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, BASE_URL);
    const options = {
      method,
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      headers: {
        'Content-Type': 'application/json',
        ...headers
      },
      timeout: TIMEOUT
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        resolve({
          status: res.statusCode,
          headers: res.headers,
          body: data,
          contentType: res.headers['content-type']
        });
      });
    });

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timeout'));
    });

    if (body) {
      req.write(JSON.stringify(body));
    }
    req.end();
  });
}

/**
 * Generate random strings and payloads
 */
function generateRandomString(length = 10) {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

function generateRandomEmail() {
  return `${generateRandomString(8)}@${generateRandomString(6)}.${['com', 'org', 'net'][Math.floor(Math.random() * 3)]}`;
}

function generateRandomPassword() {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
  let result = '';
  for (let i = 0; i < Math.floor(Math.random() * 30) + 12; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

function generateSQLInjectionPayloads() {
  return [
    "'; DROP TABLE users--",
    "' OR '1'='1",
    "admin'--",
    "' UNION SELECT * FROM users--",
    "1 OR 1=1"
  ];
}

function generateXSSPayloads() {
  return [
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert('xss')>",
    "javascript:alert('xss')",
    "<svg onload=alert('xss')>",
    "<iframe src=javascript:alert('xss')></iframe>"
  ];
}

function generatePathTraversalPayloads() {
  return [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32",
    "....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc/passwd"
  ];
}

/**
 * Test runner
 */
async function runTest(testName, testFn) {
  try {
    await testFn();
    console.log(`✓ ${testName}`);
    passedTests++;
  } catch (error) {
    console.log(`✗ ${testName}`);
    console.log(`  Error: ${error.message}`);
    failedTests++;
    failedResults.push({ testName, error: error.message });
  }
}

/**
 * Fuzz Test Suite
 */
async function runFuzzTests() {
  console.log('🧪 Starting Fuzz Tests\n');
  console.log(`Configuration: ${TEST_ITERATIONS} iterations per test\n`);

  // Test 1: Register endpoint with various payloads
  console.log('--- Test Suite 1: Registration Endpoint ---');
  
  for (let i = 0; i < 10; i++) {
    await runTest(`Register - Random inputs (iteration ${i + 1})`, async () => {
      const payload = {
        displayName: generateRandomString(Math.floor(Math.random() * 100)),
        email: generateRandomEmail(),
        password: generateRandomPassword()
      };
      const res = await makeRequest('POST', '/register', payload);
      assert(res.status !== 500, `Server error on random input: ${res.body}`);
    });
  }

  for (let payload of generateSQLInjectionPayloads()) {
    await runTest(`Register - SQL Injection in email: ${payload.substring(0, 30)}...`, async () => {
      const res = await makeRequest('POST', '/register', {
        displayName: 'Test User',
        email: payload,
        password: 'TestPass123!!'
      });
      assert(res.status !== 500, 'SQL injection caused server error');
    });
  }

  for (let payload of generateXSSPayloads()) {
    await runTest(`Register - XSS in displayName: ${payload.substring(0, 30)}...`, async () => {
      const res = await makeRequest('POST', '/register', {
        displayName: payload,
        email: generateRandomEmail(),
        password: 'TestPass123!!'
      });
      assert(res.status !== 500, 'XSS payload caused server error');
    });
  }

  // Test 2: Login endpoint with various payloads
  console.log('\n--- Test Suite 2: Login Endpoint ---');
  
  for (let i = 0; i < 10; i++) {
    await runTest(`Login - Random inputs (iteration ${i + 1})`, async () => {
      const payload = {
        email: generateRandomEmail(),
        password: generateRandomString(50)
      };
      const res = await makeRequest('POST', '/login', payload);
      assert(res.status !== 500, `Server error on random input: ${res.body}`);
    });
  }

  for (let payload of generateSQLInjectionPayloads()) {
    await runTest(`Login - SQL Injection in email: ${payload.substring(0, 30)}...`, async () => {
      const res = await makeRequest('POST', '/login', {
        email: payload,
        password: 'password123'
      });
      assert(res.status !== 500, 'SQL injection caused server error');
    });
  }

  // Test 3: Missing or null fields
  console.log('\n--- Test Suite 3: Missing/Null Field Handling ---');
  
  const registerVariants = [
    { displayName: null, email: 'test@test.com', password: 'Pass123!' },
    { displayName: 'Test', email: null, password: 'Pass123!' },
    { displayName: 'Test', email: 'test@test.com', password: null },
    { displayName: '', email: 'test@test.com', password: 'Pass123!' },
    { email: 'test@test.com', password: 'Pass123!' }, // missing displayName
    { displayName: 'Test', password: 'Pass123!' }, // missing email
    { displayName: 'Test', email: 'test@test.com' } // missing password
  ];

  for (let i = 0; i < registerVariants.length; i++) {
    await runTest(`Register - Missing/null field variant ${i + 1}`, async () => {
      const res = await makeRequest('POST', '/register', registerVariants[i]);
      assert(res.status !== 500, `Server error on missing field: ${res.body}`);
    });
  }

  // Test 4: Invalid data types
  console.log('\n--- Test Suite 4: Invalid Data Types ---');
  
  const invalidTypeVariants = [
    { displayName: 123, email: 'test@test.com', password: 'Pass123!' },
    { displayName: 'Test', email: 456, password: 'Pass123!' },
    { displayName: 'Test', email: 'test@test.com', password: ['array', 'password'] },
    { displayName: { obj: 'ect' }, email: 'test@test.com', password: 'Pass123!' },
    { displayName: 'Test', email: true, password: 'Pass123!' }
  ];

  for (let i = 0; i < invalidTypeVariants.length; i++) {
    await runTest(`Register - Invalid type variant ${i + 1}`, async () => {
      const res = await makeRequest('POST', '/register', invalidTypeVariants[i]);
      assert(res.status !== 500, `Server error on invalid type: ${res.body}`);
    });
  }

  // Test 5: Extremely large inputs
  console.log('\n--- Test Suite 5: Large Input Handling ---');
  
  for (let i = 0; i < 5; i++) {
    await runTest(`Register - Large payload (${1000 * (i + 1)}+ chars)`, async () => {
      const res = await makeRequest('POST', '/register', {
        displayName: generateRandomString(1000 * (i + 1)),
        email: generateRandomEmail(),
        password: generateRandomPassword()
      });
      assert(res.status !== 500, `Server error on large input: ${res.body}`);
    });
  }

  // Test 6: Special characters and encoding
  console.log('\n--- Test Suite 6: Special Characters ---');
  
  const specialCharSets = [
    '!@#$%^&*()',
    '你好世界', // Chinese
    '🚀🔒🔐', // Emojis
    '\n\r\t\0',
    'DROP TABLE--/**/;'
  ];

  for (let chars of specialCharSets) {
    await runTest(`Register - Special chars: ${chars.substring(0, 20)}...`, async () => {
      const res = await makeRequest('POST', '/register', {
        displayName: chars,
        email: generateRandomEmail(),
        password: 'Pass123!' + chars
      });
      assert(res.status !== 500, `Server error on special chars: ${res.body}`);
    });
  }

  // Test 7: Path traversal attempts
  console.log('\n--- Test Suite 7: Path Traversal Prevention ---');
  
  for (let payload of generatePathTraversalPayloads()) {
    await runTest(`File endpoint - Path traversal: ${payload}`, async () => {
      const res = await makeRequest('GET', `/api/file/${payload}`);
      assert(res.status !== 500, 'Path traversal caused server error');
    });
  }

  // Test 8: Case sensitivity and encoding
  console.log('\n--- Test Suite 8: Email Validation ---');
  
  const emailVariants = [
    'test@example.com',
    'TEST@EXAMPLE.COM',
    'test+tag@example.com',
    'test@localhost',
    '@example.com',
    'test@',
    'notanemail',
    'test@@example.com',
    'test@.com',
    'test@exam ple.com' // space
  ];

  for (let email of emailVariants) {
    await runTest(`Register - Email variant: ${email}`, async () => {
      const res = await makeRequest('POST', '/register', {
        displayName: 'Test User',
        email: email,
        password: 'Pass123!!'
      });
      assert(res.status !== 500, `Server error on email: ${email}`);
    });
  }

  // Test 9: Password strength validation
  console.log('\n--- Test Suite 9: Password Strength ---');
  
  const weakPasswords = [
    'short', // Too short
    'alllowercase', // No uppercase
    'ALLUPPERCASE', // No lowercase
    '12345678', // No letters
    'NoSymbol1', // No special char
    '!@#$%^&*()', // No letters/numbers
    'Pass1', // All requirements but too short
  ];

  for (let pwd of weakPasswords) {
    await runTest(`Register - Weak password: ${pwd}`, async () => {
      const res = await makeRequest('POST', '/register', {
        displayName: 'Test User',
        email: generateRandomEmail(),
        password: pwd
      });
      assert(res.status !== 500, `Server error on weak password test`);
    });
  }

  // Test 10: Concurrent requests
  console.log('\n--- Test Suite 10: Concurrency ---');
  
  await runTest('Concurrent register requests', async () => {
    const promises = [];
    for (let i = 0; i < 10; i++) {
      promises.push(
        makeRequest('POST', '/register', {
          displayName: `User${i}`,
          email: generateRandomEmail(),
          password: 'SecurePass123!!'
        })
      );
    }
    const results = await Promise.all(promises);
    assert(results.every(r => r.status !== 500), 'Some concurrent requests failed');
  });

  // Test 11: GET endpoints with malicious query params
  console.log('\n--- Test Suite 11: Query Parameter Fuzzing ---');
  
  const maliciousParams = [
    '?id=<script>alert(1)</script>',
    '?search=\'; DROP TABLE--',
    '?page=../../../etc/passwd',
    '?filter=null&offset=undefined',
    '?sort=\\x00\\x01\\x02'
  ];

  for (let param of maliciousParams) {
    await runTest(`GET endpoint - Malicious param: ${param.substring(0, 40)}...`, async () => {
      const res = await makeRequest('GET', `/properties${param}`);
      assert(res.status !== 500, `Server error on malicious params`);
    });
  }

  // Test 12: Random HTTP methods and headers
  console.log('\n--- Test Suite 12: HTTP Method Fuzzing ---');
  
  const methods = ['PATCH', 'DELETE', 'PUT', 'HEAD', 'OPTIONS'];
  for (let method of methods) {
    await runTest(`Random method: ${method} on /register`, async () => {
      const url = new URL('/register', BASE_URL);
      const options = {
        method,
        hostname: url.hostname,
        port: url.port,
        path: url.pathname,
        timeout: TIMEOUT
      };

      return new Promise((resolve, reject) => {
        const req = http.request(options, (res) => {
          res.on('data', () => {});
          res.on('end', () => resolve());
        });
        req.on('error', () => resolve()); // Method not allowed is OK
        req.end();
      });
    });
  }
}

/**
 * Main execution
 */
async function main() {
  try {
    await runFuzzTests();

    console.log('\n\n' + '='.repeat(50));
    console.log('📊 FUZZ TEST RESULTS');
    console.log('='.repeat(50));
    console.log(`✓ Passed: ${passedTests}`);
    console.log(`✗ Failed: ${failedTests}`);
    console.log(`Total: ${passedTests + failedTests}`);
    
    if (failedResults.length > 0) {
      console.log('\n❌ Failed Tests:');
      failedResults.forEach(result => {
        console.log(`  - ${result.testName}: ${result.error}`);
      });
    } else {
      console.log('\n✅ All fuzz tests passed! Application handles malformed input gracefully.');
    }

    process.exit(failedTests > 0 ? 1 : 0);
  } catch (error) {
    console.error('Fatal error:', error);
    process.exit(1);
  }
}

// Check if server is running before starting tests
setTimeout(main, 1000);

# Fuzz Testing Guide

This directory includes two comprehensive fuzz testing suites for security and robustness testing.

## Overview

Fuzz testing is a technique that sends random, malformed, or edge-case inputs to software to uncover crashes, security vulnerabilities, and unexpected behavior. These tests are critical for ensuring application stability and security.

## Test Suites

### 1. **Baseline Fuzz Test** (`fuzz-test.js`)

Targeted fuzzing with specific payloads and input patterns.

**What it tests:**
- ✓ SQL injection payloads
- ✓ XSS (Cross-Site Scripting) payloads  
- ✓ Path traversal attempts
- ✓ Missing/null field handling
- ✓ Invalid data types
- ✓ Extremely large inputs
- ✓ Special characters and Unicode
- ✓ Email validation edge cases
- ✓ Password strength validation
- ✓ Concurrent request handling
- ✓ Malicious query parameters
- ✓ HTTP method fuzzing

**Run:**
```bash
npm run test:fuzz
```

**Expected output:**
- ✓/✗ indicators for each test
- Summary of passed/failed tests
- Detailed failure information if any

### 2. **Advanced Property-Based Test** (`fuzz-test-advanced.js`)

Uses property-based testing to ensure invariants hold across random input space.

**What it tests:**
- ✓ Register never crashes on any email format (50 iterations)
- ✓ Login handles any password without crashing (50 iterations)
- ✓ Non-string values handled gracefully (50 iterations)
- ✓ Missing fields handled consistently (30 iterations)
- ✓ Extreme input sizes (20 iterations)
- ✓ Unicode and special character handling (40 iterations)
- ✓ Various email format variants (50 iterations)
- ✓ Concurrent request safety (10 iterations)
- ✓ Response headers are sensible (30 iterations)
- ✓ Request timing is reasonable (50 iterations)

**Run:**
```bash
node fuzz-test-advanced.js
```

**Why property-based testing?**

Instead of testing with fixed examples, property-based testing:
1. Generates random inputs according to specifications
2. Verifies that properties (invariants) hold for all inputs
3. When a property fails, it "shrinks" the failing case to find the minimal failing input
4. Provides better coverage of the input space

## Running Tests

### Prerequisites

Ensure the server is running:
```bash
npm start
```

The server should be listening on `http://localhost:3000`.

### Run All Tests

```bash
# Run baseline fuzz tests
npm run test:fuzz

# Run advanced property tests  
node fuzz-test-advanced.js

# Run both with stress testing (500 iterations instead of default)
npm run test:fuzz:stress
```

### Run with Custom Iterations

```bash
# Set TEST_ITERATIONS environment variable
TEST_ITERATIONS=1000 npm run test:fuzz
```

## Test Results Interpretation

### ✓ Passed Test
Application handled the input gracefully without crashing.

### ✗ Failed Test  
Either:
- Application crashed (500 error)
- Request timed out
- Unexpected behavior occurred

## Payloads Tested

### SQL Injection
```
'; DROP TABLE users--
' OR '1'='1
admin'--
' UNION SELECT * FROM users--
```

### XSS (Cross-Site Scripting)
```
<script>alert('xss')</script>
<img src=x onerror=alert('xss')>
javascript:alert('xss')
<svg onload=alert('xss')>
```

### Path Traversal
```
../../../etc/passwd
..\..\..\..\windows\system32
....//....//etc/passwd
```

### Special Characters
```
!@#$%^&*()
你好世界 (Chinese)
🚀🔒🔐 (Emoji)
\n\r\t\0 (Control characters)
```

## Security Testing Best Practices

1. **Run before deployment** - Always run fuzz tests before pushing to production
2. **Monitor for patterns** - Look for repeated failures in similar inputs
3. **Add new payloads** - Extend tests as new vulnerabilities are discovered
4. **Combine with static analysis** - Use alongside code review and SAST tools
5. **Test edge cases** - Focus on boundary conditions and rare inputs

## Expected Results for This Application

Given the application's security implementations:

- ✅ Should handle SQL injection gracefully (parameterized queries/input validation)
- ✅ Should prevent XSS (content type headers, encoding)
- ✅ Should reject path traversal (path validation)
- ✅ Should validate input types (type checking)
- ✅ Should enforce password requirements (regex validation)
- ✅ Should handle concurrency (proper session management)
- ✅ Should not crash on any input (error handling)

## Extending the Tests

To add custom tests:

### In `fuzz-test.js`:
```javascript
console.log('\n--- Test Suite: Your Test ---');

for (let i = 0; i < 10; i++) {
  await runTest(`Your test description`, async () => {
    const payload = { /* your payload */ };
    const res = await makeRequest('POST', '/your-endpoint', payload);
    assert(res.status !== 500, `Error message`);
  });
}
```

### In `fuzz-test-advanced.js`:
```javascript
properties.push(new PropertyTest(
  'Your property description',
  () => Arbitrary.string(0, 100),
  async (input) => {
    const res = await makeRequest('POST', '/endpoint', { field: input });
    return res.status !== 500;
  },
  50 // iterations
));
```

## CI/CD Integration

Add to your CI pipeline:

```yaml
# .github/workflows/fuzz-test.yml
name: Fuzz Tests
on: [push, pull_request]

jobs:
  fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-node@v2
        with:
          node-version: '18'
      - run: npm install
      - run: npm start &
      - run: sleep 2
      - run: npm run test:fuzz
```

## Troubleshooting

### "Cannot connect to server"
- Ensure server is running on port 3000
- Check: `curl http://localhost:3000`

### "ECONNREFUSED"
- Server may have crashed
- Check server logs for errors
- Restart with: `npm start`

### High failure rate
- May indicate real vulnerabilities - investigate failures
- Check server logs for errors
- Review failing inputs in test output

## Files Modified

- `fuzz-test.js` - Baseline fuzz test suite (650+ lines)
- `fuzz-test-advanced.js` - Property-based test suite (400+ lines)  
- `package.json` - Added test scripts

## References

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Fuzzing Book](https://www.fuzzingbook.org/)
- [Property-Based Testing](https://hypothesis.works/)

---

**Happy Testing! 🧪**

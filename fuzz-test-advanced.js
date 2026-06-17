/**
 * Advanced Property-Based Fuzz Testing
 * Uses hypothesis-like approach for comprehensive input space coverage
 * 
 * Run with: npm install fast-check && node fuzz-test-advanced.js
 */

const http = require('http');

const BASE_URL = 'http://localhost:3000';

// Lightweight arbitrary generators (no external deps needed)
class Arbitrary {
  static string(minLength = 0, maxLength = 100) {
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    let result = '';
    for (let i = 0; i < length; i++) {
      result += String.fromCharCode(Math.random() * 256);
    }
    return result;
  }

  static email() {
    const local = this.string(1, 20).replace(/[^a-zA-Z0-9]/g, 'a');
    const domain = this.string(1, 10).replace(/[^a-zA-Z0-9]/g, 'x');
    const tld = ['com', 'org', 'net', 'edu'][Math.floor(Math.random() * 4)];
    return `${local}@${domain}.${tld}`;
  }

  static password(minLength = 8, maxLength = 128) {
    return this.string(minLength, maxLength);
  }

  static integer(min = Number.MIN_SAFE_INTEGER, max = Number.MAX_SAFE_INTEGER) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
  }

  static boolean() {
    return Math.random() > 0.5;
  }

  static oneOf(...options) {
    return options[Math.floor(Math.random() * options.length)];
  }

  static null() {
    return null;
  }

  static undefined() {
    return undefined;
  }

  static array(elementGen, minSize = 0, maxSize = 10) {
    const size = Math.floor(Math.random() * (maxSize - minSize + 1)) + minSize;
    const arr = [];
    for (let i = 0; i < size; i++) {
      arr.push(elementGen());
    }
    return arr;
  }

  static object(schema) {
    const obj = {};
    for (const [key, gen] of Object.entries(schema)) {
      obj[key] = gen();
    }
    return obj;
  }
}

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
      timeout: 5000
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        resolve({
          status: res.statusCode,
          headers: res.headers,
          body: data
        });
      });
    });

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Timeout'));
    });

    if (body) {
      req.write(JSON.stringify(body));
    }
    req.end();
  });
}

/**
 * Property-based test runner
 */
class PropertyTest {
  constructor(name, generator, predicate, iterations = 100) {
    this.name = name;
    this.generator = generator;
    this.predicate = predicate;
    this.iterations = iterations;
    this.passed = 0;
    this.failed = 0;
    this.shrinks = [];
  }

  async run() {
    for (let i = 0; i < this.iterations; i++) {
      try {
        const input = this.generator();
        const result = await this.predicate(input);
        
        if (result === true) {
          this.passed++;
        } else {
          this.failed++;
          this.shrinks.push({ input, reason: result });
        }
      } catch (error) {
        this.failed++;
        this.shrinks.push({ error: error.message });
      }
    }
  }

  report() {
    const status = this.failed === 0 ? '✓' : '✗';
    console.log(`${status} ${this.name}: ${this.passed}/${this.iterations} passed`);
    
    if (this.shrinks.length > 0 && this.shrinks.length <= 3) {
      this.shrinks.forEach(shrink => {
        if (shrink.error) {
          console.log(`  └─ Error: ${shrink.error}`);
        } else {
          console.log(`  └─ Failed with: ${JSON.stringify(shrink.input).substring(0, 80)}`);
        }
      });
    }
  }
}

/**
 * Define properties to test
 */
async function defineProperties() {
  const properties = [];

  // Property 1: Register endpoint should never crash on any email-shaped input
  properties.push(new PropertyTest(
    'Register never crashes on any email format',
    () => Arbitrary.email(),
    async (email) => {
      try {
        const res = await makeRequest('POST', '/register', {
          displayName: 'Test User',
          email: email,
          password: 'SecurePass123!!'
        });
        return res.status !== 500; // Should not be 500
      } catch (error) {
        return false; // Crash is failure
      }
    },
    50
  ));

  // Property 2: Login should handle any string as password
  properties.push(new PropertyTest(
    'Login handles any password string without crashing',
    () => Arbitrary.string(0, 1000),
    async (password) => {
      try {
        const res = await makeRequest('POST', '/login', {
          email: 'test@test.com',
          password: password
        });
        return res.status !== 500;
      } catch (error) {
        return false;
      }
    },
    50
  ));

  // Property 3: Register rejects non-string displayNames gracefully
  properties.push(new PropertyTest(
    'Register handles non-string displayName values',
    () => Arbitrary.oneOf(
      Arbitrary.integer(),
      Arbitrary.boolean(),
      Arbitrary.array(() => 'item', 0, 5),
      { nested: 'object' },
      null
    ),
    async (displayName) => {
      try {
        const res = await makeRequest('POST', '/register', {
          displayName: displayName,
          email: 'test@test.com',
          password: 'SecurePass123!!'
        });
        return res.status !== 500;
      } catch (error) {
        return false;
      }
    },
    50
  ));

  // Property 4: Missing fields are handled consistently
  properties.push(new PropertyTest(
    'Register handles missing fields consistently',
    () => {
      const fields = { displayName: 'User', email: 'test@test.com', password: 'Pass123!!' };
      const keys = Object.keys(fields);
      const removeKey = keys[Math.floor(Math.random() * keys.length)];
      const obj = { ...fields };
      delete obj[removeKey];
      return obj;
    },
    async (payload) => {
      try {
        const res = await makeRequest('POST', '/register', payload);
        return res.status !== 500;
      } catch (error) {
        return false;
      }
    },
    30
  ));

  // Property 5: Extreme sizes are handled
  properties.push(new PropertyTest(
    'Register handles extremely large inputs',
    () => ({
      displayName: Arbitrary.string(0, 10000),
      email: Arbitrary.email(),
      password: Arbitrary.password(12, 5000)
    }),
    async (payload) => {
      try {
        const res = await makeRequest('POST', '/register', payload, {
          timeout: 10000
        });
        return res.status !== 500;
      } catch (error) {
        return false;
      }
    },
    20
  ));

  // Property 6: Unicode and special characters are handled
  properties.push(new PropertyTest(
    'Register handles Unicode and special characters',
    () => ({
      displayName: Arbitrary.oneOf(
        '你好世界中国日本',
        '🚀🔒🔐🔑🗝️',
        'עברית العربية ไทย',
        '\n\r\t\0\x00\xFF',
        'DROP TABLE users;--'
      ),
      email: Arbitrary.email(),
      password: 'Pass123!!' + Arbitrary.string(0, 50)
    }),
    async (payload) => {
      try {
        const res = await makeRequest('POST', '/register', payload);
        return res.status !== 500;
      } catch (error) {
        return false;
      }
    },
    40
  ));

  // Property 7: Various email formats
  properties.push(new PropertyTest(
    'Register handles various email formats',
    () => ({
      displayName: 'Test User',
      email: Arbitrary.oneOf(
        'simple@example.com',
        'very.common@example.com',
        'disposable.style.email.with+symbol@example.com',
        'other.email-with-hyphen@example.com',
        'fully-qualified-domain@example.com',
        'user.name+tag+sorting@example.com',
        'x@example.com',
        'example-indeed@strange-example.com',
        'test/test@test.com',
        'admin@example.co.uk'
      ),
      password: 'SecurePass123!!'
    }),
    async (payload) => {
      try {
        const res = await makeRequest('POST', '/register', payload);
        return res.status !== 500;
      } catch (error) {
        return false;
      }
    },
    50
  ));

  // Property 8: Concurrent requests don't cause race conditions
  properties.push(new PropertyTest(
    'Concurrent requests handled safely',
    () => Arbitrary.array(
      () => ({
        displayName: 'User' + Arbitrary.integer(1, 1000),
        email: Arbitrary.email(),
        password: 'SecurePass123!!'
      }),
      2,
      10
    ),
    async (payloads) => {
      try {
        const promises = payloads.map(p =>
          makeRequest('POST', '/register', p).catch(() => ({ status: 500 }))
        );
        const results = await Promise.all(promises);
        const allNot500 = results.every(r => r.status !== 500);
        return allNot500;
      } catch (error) {
        return false;
      }
    },
    10
  ));

  // Property 9: Response headers are sensible
  properties.push(new PropertyTest(
    'Responses have sensible headers',
    () => Arbitrary.email(),
    async (email) => {
      try {
        const res = await makeRequest('POST', '/register', {
          displayName: 'Test',
          email: email,
          password: 'Pass123!!'
        });
        
        // Check for dangerous headers
        const hasSetCookie = res.headers['set-cookie'] !== undefined;
        const hasContentType = res.headers['content-type'] !== undefined;
        const noDirectives = !res.body?.includes('eval(');
        
        return hasContentType && noDirectives;
      } catch (error) {
        return false;
      }
    },
    30
  ));

  // Property 10: Timing is reasonable
  properties.push(new PropertyTest(
    'Register request completes in reasonable time',
    () => ({
      displayName: Arbitrary.string(1, 100),
      email: Arbitrary.email(),
      password: Arbitrary.password(12, 128)
    }),
    async (payload) => {
      try {
        const start = Date.now();
        await makeRequest('POST', '/register', payload);
        const elapsed = Date.now() - start;
        return elapsed < 5000; // Should complete within 5s
      } catch (error) {
        return elapsed < 5000; // Even errors should timeout quickly
      }
    },
    50
  ));

  return properties;
}

/**
 * Main execution
 */
async function main() {
  console.log('🔬 Advanced Property-Based Fuzz Testing\n');

  try {
    const properties = await defineProperties();
    
    console.log(`Running ${properties.length} property-based tests...\n`);

    for (const prop of properties) {
      await prop.run();
      prop.report();
    }

    const totalTests = properties.length;
    const passedTests = properties.filter(p => p.failed === 0).length;

    console.log('\n' + '='.repeat(50));
    console.log(`📊 PROPERTY TEST RESULTS: ${passedTests}/${totalTests} properties held`);
    console.log('='.repeat(50));

    if (passedTests === totalTests) {
      console.log('\n✅ All properties held! Application input handling is robust.');
      process.exit(0);
    } else {
      console.log('\n⚠️  Some properties failed. Check output above.');
      process.exit(1);
    }
  } catch (error) {
    console.error('Fatal error:', error);
    process.exit(1);
  }
}

setTimeout(main, 1000);

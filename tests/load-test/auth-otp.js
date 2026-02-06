import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');

// Test configuration
export const options = {
  stages: [
    { duration: '30s', target: 20 },   // Ramp up to 20 users
    { duration: '1m', target: 50 },    // Stay at 50 users
    { duration: '2m', target: 100 },   // Ramp up to 100 users
    { duration: '1m', target: 100 },   // Stay at 100 users
    { duration: '30s', target: 0 },    // Ramp down to 0 users
  ],
  thresholds: {
    http_req_duration: ['p(95)<500'], // 95% of requests should be below 500ms
    http_req_failed: ['rate<0.1'],     // Error rate should be less than 10%
    errors: ['rate<0.1'],
  },
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:9001';

// Test phone numbers (will cycle through)
const testPhones = [
  '+989011793041',
  '+989121234567',
  '+989131234567',
  '+989141234567',
  '+989151234567',
];

export default function () {
  // Select random phone
  const phone = testPhones[Math.floor(Math.random() * testPhones.length)];

  // Test 1: Send OTP
  const sendOTPPayload = JSON.stringify({
    phone: phone,
  });

  const sendOTPParams = {
    headers: {
      'Content-Type': 'application/json',
    },
    tags: { name: 'SendOTP' },
  };

  const sendOTPRes = http.post(
    `${BASE_URL}/api/v1/auth/otp/send`,
    sendOTPPayload,
    sendOTPParams
  );

  const sendOTPSuccess = check(sendOTPRes, {
    'SendOTP: status is 200 or 429': (r) => r.status === 200 || r.status === 429,
    'SendOTP: response time < 500ms': (r) => r.timings.duration < 500,
    'SendOTP: has success field': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.hasOwnProperty('success') || body.hasOwnProperty('error');
      } catch (e) {
        return false;
      }
    },
  });

  errorRate.add(!sendOTPSuccess);

  // If we got 429 (rate limited), that's expected behavior
  if (sendOTPRes.status === 429) {
    console.log(`Rate limited for phone ${phone} - expected behavior`);
  }

  // Wait a bit before next request
  sleep(1);

  // Test 2: Verify OTP (will fail without real code, but tests endpoint)
  const verifyOTPPayload = JSON.stringify({
    phone: phone,
    code: '123456', // Mock code
  });

  const verifyOTPParams = {
    headers: {
      'Content-Type': 'application/json',
    },
    tags: { name: 'VerifyOTP' },
  };

  const verifyOTPRes = http.post(
    `${BASE_URL}/api/v1/auth/otp/verify`,
    verifyOTPPayload,
    verifyOTPParams
  );

  const verifyOTPSuccess = check(verifyOTPRes, {
    'VerifyOTP: status is 400 or 401': (r) => r.status === 400 || r.status === 401, // Expected to fail with mock code
    'VerifyOTP: response time < 300ms': (r) => r.timings.duration < 300,
  });

  errorRate.add(!verifyOTPSuccess);

  sleep(1);
}

export function handleSummary(data) {
  return {
    'summary.json': JSON.stringify(data),
    stdout: textSummary(data, { indent: ' ', enableColors: true }),
  };
}

function textSummary(data, options) {
  const indent = options.indent || '';
  const enableColors = options.enableColors || false;

  let summary = '\n';
  summary += `${indent}Test Summary:\n`;
  summary += `${indent}================\n`;
  summary += `${indent}Duration: ${data.state.testRunDurationMs / 1000}s\n`;
  summary += `${indent}Iterations: ${data.metrics.iterations.values.count}\n`;
  summary += `${indent}VUs: ${data.metrics.vus.values.value}\n`;
  summary += `${indent}\n`;
  summary += `${indent}HTTP Metrics:\n`;
  summary += `${indent}  Requests: ${data.metrics.http_reqs.values.count}\n`;
  summary += `${indent}  Failed: ${data.metrics.http_req_failed.values.rate * 100}%\n`;
  summary += `${indent}  Duration (avg): ${data.metrics.http_req_duration.values.avg}ms\n`;
  summary += `${indent}  Duration (p95): ${data.metrics.http_req_duration.values['p(95)']}ms\n`;
  
  return summary;
}

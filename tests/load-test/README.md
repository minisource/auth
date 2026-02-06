# Load Testing Scripts

This directory contains k6 load testing scripts for the Minisource microservices.

## Prerequisites

Install k6:
```bash
# Windows (using Chocolatey)
choco install k6

# macOS (using Homebrew)
brew install k6

# Or download from https://k6.io/docs/getting-started/installation/
```

## Running Tests

### Auth Service - OTP Flow
Tests the OTP send and verify endpoints with realistic load patterns.

```bash
# Basic run
k6 run auth-otp.js

# Custom configuration
k6 run --vus 50 --duration 2m auth-otp.js

# With custom base URL
k6 run --env BASE_URL=http://production-server:9001 auth-otp.js

# Save results to file
k6 run --out json=auth-results.json auth-otp.js
```

**Load Profile:**
- Ramp up: 30s to 20 users
- Stay: 1m at 50 users
- Peak: 2m at 100 users
- Sustain: 1m at 100 users
- Ramp down: 30s to 0 users

**Thresholds:**
- 95% of requests < 500ms
- Error rate < 10%

### Notifier Service - Send Notifications
Tests notification sending (SMS, Email) and retrieval endpoints.

```bash
# Basic run
k6 run notifier-send.js

# With API key
k6 run --env API_KEY=your-api-key notifier-send.js

# Custom base URL
k6 run --env BASE_URL=http://localhost:9002 --env API_KEY=test-key notifier-send.js
```

**Load Profile:**
- Ramp up: 30s to 10 users
- Stay: 1m at 30 users
- Peak: 2m at 50 users
- Sustain: 1m at 50 users
- Ramp down: 30s to 0 users

**Thresholds:**
- 95% of requests < 1000ms
- Error rate < 5%

## Understanding Results

### Key Metrics

- **http_req_duration**: Time spent waiting for response
  - avg: Average response time
  - p(95): 95% of requests faster than this
  - p(99): 99% of requests faster than this

- **http_req_failed**: Percentage of failed HTTP requests

- **iterations**: Total number of complete test iterations

- **vus**: Virtual Users (concurrent users)

### Good Performance Indicators

✅ P95 response time below threshold
✅ Error rate below 1%
✅ No timeouts or connection errors
✅ Linear scaling with increased load

### Warning Signs

⚠️ P95 response time increasing sharply
⚠️ Error rate above threshold
⚠️ Rate limiting (429 errors) - may be expected
⚠️ Timeouts or connection refused

## Advanced Usage

### Cloud Execution (k6 Cloud)
```bash
k6 cloud auth-otp.js
```

### Distributed Load Testing
```bash
# Run on multiple machines
k6 run --execution-mode distributed auth-otp.js
```

### Custom Thresholds
```bash
k6 run --threshold http_req_duration=p(95)<300 auth-otp.js
```

## CI/CD Integration

Add to GitHub Actions:
```yaml
- name: Run load tests
  run: |
    k6 run --quiet scripts/load-test/auth-otp.js
```

## Monitoring During Tests

While running tests, monitor:
- Prometheus metrics at http://localhost:9090
- Grafana dashboards at http://localhost:3000
- Service logs
- Database connections
- CPU and memory usage

## Best Practices

1. **Start Small**: Begin with lower VUs and ramp up
2. **Monitor Resources**: Watch CPU, memory, database connections
3. **Analyze Results**: Look for bottlenecks, not just pass/fail
4. **Test Realistic Scenarios**: Use real-world data patterns
5. **Run Multiple Times**: Ensure consistent results
6. **Test Different Times**: Peak vs off-peak behavior

## Troubleshooting

### High Error Rates
- Check service logs
- Verify database connections
- Check rate limiting configuration
- Ensure sufficient resources

### Slow Response Times
- Check database query performance
- Look for N+1 queries
- Verify caching is working
- Check network latency

### Connection Errors
- Verify services are running
- Check firewall rules
- Ensure correct URLs and ports
- Verify load balancer configuration

// SPDX-License-Identifier: MIT
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  PREFLIGHT_SCHEMA,
  endpointHostname,
  parseArguments,
  runSonarScanner,
} from '../tools/run_sonar_scanner_with_hosts_override.mjs';

function report(source = 'tailnet_ip') {
  return {
    schema: PREFLIGHT_SCHEMA,
    status: 'pass',
    dns_resolved: source === 'dns',
    fallback_configured: true,
    fallback_attempted: source === 'tailnet_ip',
    connection_address_source: source,
    tcp_connected: true,
    tls_verified: true,
    http_status: 200,
    sonar_status: 'UP',
    failure_stage: null,
  };
}

function tempDir(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'test-nvdriver-sonar-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

test('verified fallback maps only the scanner JVM and retains the TLS hostname', t => {
  const directory = tempDir(t);
  const hostsSource = path.join(directory, 'hosts-source');
  fs.writeFileSync(hostsSource,
    '127.0.0.1 localhost\n192.0.2.12 pc4.tail0c55ff.ts.net alias\n');
  let observation;

  const result = runSonarScanner(
    'https://pc4.tail0c55ff.ts.net:8443', '100.76.101.48', report(),
    ['-Dsonar.projectKey=fixture'], {
      hostsSource,
      baseEnvironment: { JAVA_TOOL_OPTIONS: '-Xmx512m' },
      logger: () => {},
      runner(command, args, options) {
        assert.equal(command, 'sonar-scanner');
        assert.deepEqual(args, ['-Dsonar.projectKey=fixture']);
        assert.equal(options.stdio, 'inherit');
        const option = options.env.JAVA_TOOL_OPTIONS.split(' ')
          .find(item => item.startsWith('-Djdk.net.hosts.file='));
        const hostsPath = option.split('=', 2)[1];
        observation = {
          hostsPath,
          hosts: fs.readFileSync(hostsPath, 'utf8'),
          javaOptions: options.env.JAVA_TOOL_OPTIONS,
          endpoint: options.env.SONAR_HOST_URL,
        };
        return { status: 7, signal: null };
      },
    },
  );

  assert.equal(result, 7);
  assert.match(observation.hosts, /127\.0\.0\.1 localhost/);
  assert.match(observation.hosts, /192\.0\.2\.12 alias/);
  assert.doesNotMatch(observation.hosts, /192\.0\.2\.12 pc4\.tail0c55ff\.ts\.net/);
  assert.match(observation.hosts, /100\.76\.101\.48 pc4\.tail0c55ff\.ts\.net/);
  assert.match(observation.javaOptions, /-Xmx512m/);
  assert.equal(observation.endpoint, 'https://pc4.tail0c55ff.ts.net:8443');
  assert.equal(fs.existsSync(observation.hostsPath), false);
});

test('DNS success uses the normal JVM resolver', () => {
  let observed;
  const result = runSonarScanner('https://sonar.internal.example', '100.76.101.48',
    report('dns'), ['-Dsonar.projectKey=fixture'], {
      baseEnvironment: { JAVA_TOOL_OPTIONS: '-Xmx512m' },
      logger: () => {},
      runner(_command, _args, options) { observed = options.env; return { status: 0 }; },
    });
  assert.equal(result, 0);
  assert.equal(observed.JAVA_TOOL_OPTIONS, '-Xmx512m');
  assert.equal(observed.SONAR_HOST_URL, 'https://sonar.internal.example');
});

test('rejects unsafe endpoints and unhealthy or inconsistent preflight before launch', () => {
  let launchCount = 0;
  const runner = () => { launchCount += 1; return { status: 0 }; };
  for (const endpoint of [
    'http://sonar.internal.example',
    'https://user@sonar.internal.example',
    'https://sonar.internal.example/?mode=unsafe',
  ]) {
    assert.throws(() => endpointHostname(endpoint), { message: 'invalid_endpoint' });
  }
  for (const [key, value] of [
    ['status', 'fail'],
    ['tls_verified', false],
    ['sonar_status', 'DOWN'],
    ['connection_address_source', 'none'],
  ]) {
    const invalid = report();
    invalid[key] = value;
    assert.throws(() => runSonarScanner('https://sonar.internal.example',
      '100.76.101.48', invalid, ['-Dsonar.projectKey=fixture'], { runner }));
  }
  assert.equal(launchCount, 0);
});

test('rejects invalid fallback address and empty scanner arguments', () => {
  assert.throws(() => runSonarScanner('https://sonar.internal.example', 'not-an-ip',
    report(), ['-Dsonar.projectKey=fixture']), { message: 'invalid_fallback_ip' });
  assert.throws(() => runSonarScanner('https://sonar.internal.example', '100.76.101.48',
    report(), []), { message: 'scanner_arguments_required' });
});

test('parses scanner arguments without expanding them into the wrapper options', () => {
  assert.deepEqual(parseArguments([
    '--preflight', 'preflight.json', '--endpoint', 'https://sonar.example',
    '--fallback-ip', '100.76.101.48', '--', '-Dsonar.projectKey=fixture',
  ]), {
    preflight: 'preflight.json',
    endpoint: 'https://sonar.example',
    fallbackIp: '100.76.101.48',
    scannerArguments: ['-Dsonar.projectKey=fixture'],
  });
});

test('the JVM honors the per-process hosts file supplied through JAVA_TOOL_OPTIONS', t => {
  const directory = tempDir(t);
  const hosts = path.join(directory, 'hosts');
  const source = path.join(directory, 'ResolveHost.java');
  fs.writeFileSync(hosts, '192.0.2.77 resolver-fixture.invalid\n');
  fs.writeFileSync(source,
    'import java.net.InetAddress; class ResolveHost { public static void main(String[] a) throws Exception { System.out.print(InetAddress.getByName(a[0]).getHostAddress()); } }\n');

  const result = spawnSync('java', [source, 'resolver-fixture.invalid'], {
    encoding: 'utf8',
    env: { ...process.env, JAVA_TOOL_OPTIONS: `-Djdk.net.hosts.file=${hosts}` },
    timeout: 15_000,
  });
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, '192.0.2.77');
});

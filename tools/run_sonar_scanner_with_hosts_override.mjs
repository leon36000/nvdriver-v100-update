#!/usr/bin/env node
// SPDX-License-Identifier: MIT
/** Run SonarScanner with a verified, per-process DNS override when required. */

import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

export const PREFLIGHT_SCHEMA = 'nvidia-hybrid-sonar-runner-probe-v1';

export function endpointHostname(endpoint) {
  let parsed;
  try {
    parsed = new URL(endpoint);
  } catch {
    throw new Error('invalid_endpoint');
  }
  if (parsed.protocol !== 'https:' || !parsed.hostname || parsed.username ||
      parsed.password || parsed.search || parsed.hash) {
    throw new Error('invalid_endpoint');
  }
  return parsed.hostname;
}

export function preflightUsesTailnetIp(report) {
  if (!report || typeof report !== 'object' || Array.isArray(report) ||
      report.schema !== PREFLIGHT_SCHEMA) {
    throw new Error('invalid_preflight');
  }
  if (report.status !== 'pass' || report.tcp_connected !== true ||
      report.tls_verified !== true || report.http_status !== 200 ||
      report.sonar_status !== 'UP' || report.failure_stage !== null) {
    throw new Error('preflight_not_healthy');
  }
  if (report.connection_address_source === 'dns' &&
      report.dns_resolved === true) {
    return false;
  }
  if (report.connection_address_source === 'tailnet_ip' &&
      report.fallback_attempted === true &&
      report.fallback_configured === true) {
    return true;
  }
  throw new Error('inconsistent_preflight');
}

export function writeHostsOverride(source, destination, address, hostname) {
  if (net.isIP(address) === 0) throw new Error('invalid_hosts_input');

  let sourceText;
  try {
    sourceText = fs.readFileSync(source, 'utf8');
  } catch {
    throw new Error('invalid_hosts_input');
  }

  const wanted = hostname.toLocaleLowerCase('en-US');
  const kept = [];
  for (const originalLine of sourceText.split(/\r?\n/)) {
    if (originalLine === '' && kept.length === 0) continue;
    const [body, ...commentParts] = originalLine.split('#', 2);
    const fields = body.trim().split(/\s+/).filter(Boolean);
    if (fields.length >= 2 &&
        fields.slice(1).some(name => name.toLocaleLowerCase('en-US') === wanted)) {
      const aliases = fields.slice(1).filter(
        name => name.toLocaleLowerCase('en-US') !== wanted);
      const comment = commentParts.length ? ` #${commentParts[0]}` : '';
      if (aliases.length) kept.push(`${fields[0]} ${aliases.join(' ')}${comment}`);
      else if (comment) kept.push(comment.trimStart());
      continue;
    }
    kept.push(originalLine);
  }
  kept.push(`${address} ${hostname}`);

  try {
    fs.writeFileSync(destination, `${kept.join('\n').replace(/\n+$/, '')}\n`,
      { encoding: 'utf8', mode: 0o600 });
  } catch {
    throw new Error('hosts_override_write_failed');
  }
}

export function runSonarScanner(endpoint, fallbackIp, report, scannerArguments, {
  hostsSource = '/etc/hosts',
  baseEnvironment = process.env,
  runner = spawnSync,
  logger = line => console.log(line),
} = {}) {
  if (!Array.isArray(scannerArguments) || scannerArguments.length === 0) {
    throw new Error('scanner_arguments_required');
  }
  const hostname = endpointHostname(endpoint);
  const useOverride = preflightUsesTailnetIp(report);
  let address = null;
  if (useOverride) {
    if (net.isIP(fallbackIp) === 0) throw new Error('invalid_fallback_ip');
    address = fallbackIp;
  }

  const environment = { ...baseEnvironment, SONAR_HOST_URL: endpoint };
  if (!useOverride) {
    logger(JSON.stringify({ schema: 'nvidia-hybrid-sonar-launch-v1',
      status: 'ready', dns_override: 'none' }));
    const result = runner('sonar-scanner', scannerArguments, {
      env: environment, stdio: 'inherit', shell: false,
    });
    if (result.error) throw result.error;
    return result.status ?? (result.signal ? 128 : 1);
  }

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'nvdriver-sonar-'));
  try {
    const hostsPath = path.join(directory, 'hosts');
    writeHostsOverride(hostsSource, hostsPath, address, hostname);
    const existing = (environment.JAVA_TOOL_OPTIONS || '').trim();
    const resolverOption = `-Djdk.net.hosts.file=${hostsPath}`;
    environment.JAVA_TOOL_OPTIONS = [existing, resolverOption].filter(Boolean).join(' ');
    logger(JSON.stringify({ schema: 'nvidia-hybrid-sonar-launch-v1',
      status: 'ready', dns_override: 'jdk_hosts_file' }));
    const result = runner('sonar-scanner', scannerArguments, {
      env: environment, stdio: 'inherit', shell: false,
    });
    if (result.error) throw result.error;
    if (!fs.existsSync(hostsPath)) throw new Error('hosts_override_missing');
    return result.status ?? (result.signal ? 128 : 1);
  } catch (error) {
    if (error instanceof Error && error.message === 'hosts_override_missing') throw error;
    if (error instanceof Error && error.message === 'hosts_override_write_failed') throw error;
    if (error instanceof Error && error.message === 'invalid_hosts_input') throw error;
    if (error?.code === 'ENOENT') throw error;
    throw new Error('scanner_failed');
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

export function parseArguments(argv) {
  let preflight = null;
  let endpoint = process.env.SONAR_HOST_URL || '';
  let fallbackIp = process.env.SONAR_HOST_IP || '';
  const scannerArguments = [];
  let scannerMode = false;
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (scannerMode) {
      scannerArguments.push(argument);
    } else if (argument === '--') {
      scannerMode = true;
    } else if (argument === '--preflight' && argv[index + 1]) {
      preflight = argv[++index];
    } else if (argument === '--endpoint' && argv[index + 1]) {
      endpoint = argv[++index];
    } else if (argument === '--fallback-ip' && argv[index + 1]) {
      fallbackIp = argv[++index];
    } else {
      throw new Error('invalid_arguments');
    }
  }
  if (!preflight) throw new Error('invalid_arguments');
  return { preflight, endpoint, fallbackIp, scannerArguments };
}

export function main(argv = process.argv.slice(2)) {
  let args;
  try {
    args = parseArguments(argv);
  } catch {
    console.error(JSON.stringify({ schema: 'nvidia-hybrid-sonar-launch-v1',
      status: 'fail', reason: 'invalid_arguments' }));
    return 2;
  }

  let report;
  try {
    report = JSON.parse(fs.readFileSync(args.preflight, 'utf8'));
  } catch {
    console.error(JSON.stringify({ schema: 'nvidia-hybrid-sonar-launch-v1',
      status: 'fail', reason: 'invalid_preflight' }));
    return 2;
  }
  try {
    return runSonarScanner(args.endpoint, args.fallbackIp, report,
      args.scannerArguments);
  } catch (error) {
    const reason = error?.code === 'ENOENT' ? 'scanner_unavailable' :
      new Set(['invalid_endpoint', 'preflight_not_healthy', 'inconsistent_preflight',
        'invalid_fallback_ip', 'scanner_arguments_required', 'invalid_hosts_input',
        'hosts_override_write_failed', 'hosts_override_missing']).has(error?.message)
        ? error.message : 'scanner_failed';
    console.error(JSON.stringify({ schema: 'nvidia-hybrid-sonar-launch-v1',
      status: 'fail', reason }));
    return reason === 'scanner_unavailable' ? 127 : 2;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  process.exitCode = main();
}

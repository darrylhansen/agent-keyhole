import fs from 'fs';
import path from 'path';
import { loadConfig } from '../config/loader.js';
import { spawnSidecar } from '../client/spawn.js';
import { IPCClient } from '../client/ipc-client.js';
import crypto from 'crypto';

export async function testCommand(args: string[]): Promise<void> {
  const serviceName = args.find((a) => !a.startsWith('-'));
  const configPath = getConfigPath(args);

  if (!fs.existsSync(configPath)) {
    console.error(`Error: ${configPath} not found. Run "npx keyhole init" first.`);
    process.exit(1);
  }

  const config = await loadConfig(configPath);

  const servicesToTest = serviceName
    ? [serviceName]
    : Object.keys(config.services);

  for (const name of servicesToTest) {
    if (!config.services[name]) {
      console.error(`Error: Service "${name}" not found in ${configPath}`);
      process.exit(1);
    }
  }

  console.error('Starting sidecar...');

  let handle;
  try {
    handle = await spawnSidecar(config);
  } catch (err: any) {
    console.error(`Error starting sidecar: ${err.message}`);
    process.exit(1);
  }

  console.error(`✔ Sidecar ready (PID ${handle.child.pid})\n`);

  const ipc = new IPCClient(handle.socketPath, handle.ott);
  await ipc.connect();

  let allPassed = true;

  for (const name of servicesToTest) {
    const service = config.services[name];
    const testPath = getTestPath(name, service);

    process.stderr.write(`Testing ${name}...  `);

    try {
      const response = await ipc.send({
        id: crypto.randomUUID(),
        service: name,
        method: 'GET',
        path: testPath,
        headers: {},
        bodyEncoding: 'utf8'
      });

      console.error(`→ GET ${testPath} → ${response.status} ${response.status < 400 ? 'OK' : 'FAIL'} ${response.status < 400 ? '✔' : '✗'}`);

      if (response.status >= 400) {
        allPassed = false;
      }
    } catch (err: any) {
      console.error(`→ ERROR: ${err.message} ✗`);
      allPassed = false;
    }
  }

  console.error('');
  if (allPassed) {
    console.error(`All ${servicesToTest.length} services operational.`);
  } else {
    console.error('Some services failed. Check your configuration and secrets.');
  }

  await ipc.disconnect();
  handle.child.send({ type: 'shutdown' });

  // Wait briefly for clean shutdown
  await new Promise((resolve) => setTimeout(resolve, 1000));

  if (!allPassed) process.exit(2);
}

function getTestPath(
  name: string,
  service: any
): string {
  // Common test endpoints for known services
  const testPaths: Record<string, string> = {
    github: '/user',
    openai: '/v1/models',
    anthropic: '/v1/messages',
    gemini: '/v1/models',
    stripe: '/v1/charges?limit=1'
  };

  return testPaths[name] || '/';
}

function getConfigPath(args: string[]): string {
  const configIdx = args.indexOf('--config');
  if (configIdx !== -1 && args[configIdx + 1]) {
    return path.resolve(args[configIdx + 1]);
  }
  return path.resolve('keyhole.yaml');
}

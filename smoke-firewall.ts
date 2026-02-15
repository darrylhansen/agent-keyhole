import { createKeyhole } from './src/index.js';
import { promptSecret } from './src/cli/shared.js';

async function main() {
  console.log('Starting Keyhole with autoPatch...');
  const kh = await createKeyhole({ config: './keyhole.yaml', autoPatch: true });
  console.log('Sidecar ready. State:', kh.state);

  if (kh.state === 'pending_unlock') {
    const passphrase = await promptSecret('Enter vault passphrase: ');
    await kh.unlock(passphrase);
    console.log('Vault unlocked. State:', kh.state);
  }

  // Inject placeholder env vars
  const env = kh.getSafeEnv();
  Object.assign(process.env, env);

  // Verify agent only sees placeholder
  console.log('\n--- Credential Firewall Check ---');
  console.log('GITHUB_TOKEN env:', process.env.GITHUB_TOKEN);
  console.log('Expected: KEYHOLE_MANAGED (or configured placeholder)');

  // Make a request through the intercepted fetch
  console.log('\n--- Intercepted Fetch ---');
  const res = await fetch('https://api.github.com/user');
  console.log('Status:', res.status);
  console.log('Body:', JSON.stringify(await res.json(), null, 2));

  await kh.shutdown();
  console.log('\nShutdown complete.');
}

main().catch((err) => {
  console.error('SMOKE TEST FAILED:', err);
  process.exit(1);
});

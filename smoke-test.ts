import { createKeyhole } from './src/index.js';
import { promptSecret } from './src/cli/shared.js';

async function main() {
  console.log('Starting Keyhole sidecar...');
  const kh = await createKeyhole({ config: './keyhole.yaml' });
  console.log('Sidecar ready. State:', kh.state);

  if (kh.state === 'pending_unlock') {
    const passphrase = await promptSecret('Enter vault passphrase: ');
    await kh.unlock(passphrase);
    console.log('Vault unlocked. State:', kh.state);
  }

  const github = kh.createClient('github');
  console.log('Calling GitHub API...');
  const res = await github('/user');
  console.log('Status:', res.status);
  console.log('Body:', JSON.stringify(await res.json(), null, 2));

  await kh.shutdown();
  console.log('Shutdown complete.');
}

main().catch((err) => {
  console.error('SMOKE TEST FAILED:', err);
  process.exit(1);
});

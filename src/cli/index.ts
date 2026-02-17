import { initCommand } from './init.js';
import { addCommand } from './add.js';
import { removeCommand } from './remove.js';
import { getCommand } from './get.js';
import { listCommand } from './list.js';
import { testCommand } from './test.js';
import { vaultCommand } from './vault.js';
import { migrateCommand } from './migrate.js';
import { safeRepo } from './safe-repo.js';

const VERSION = '1.0.0';

export async function runCLI(args: string[]): Promise<void> {
  const command = args[0];

  switch (command) {
    case 'init':
      await initCommand(args.slice(1));
      break;
    case 'add':
      await addCommand(args.slice(1));
      break;
    case 'remove':
      await removeCommand(args.slice(1));
      break;
    case 'get':
      await getCommand(args.slice(1));
      break;
    case 'list':
      await listCommand(args.slice(1));
      break;
    case 'test':
      await testCommand(args.slice(1));
      break;
    case 'vault':
      await vaultCommand(args.slice(1));
      break;
    case 'migrate':
      await migrateCommand(args.slice(1));
      break;
    case 'safe-repo':
      safeRepo();
      break;
    case 'version':
    case '--version':
    case '-v':
      console.error(`agent-keyhole v${VERSION}`);
      break;
    case 'help':
    case '--help':
    case '-h':
    case undefined:
      printHelp();
      break;
    default:
      console.error(`Unknown command: ${command}`);
      console.error('Run "npx keyhole help" for usage.');
      process.exit(1);
  }
}

function printHelp(): void {
  console.error(`agent-keyhole v${VERSION}
A trust boundary for LLM agents.

Usage: npx keyhole <command> [options]

Commands:
  init                    Create a keyhole.yaml config file
  add <service>           Store a secret in the OS keychain
  remove <service>        Remove a secret from the OS keychain
  get <secret-ref>        Retrieve and print a stored secret value
  list                    List configured services and secret status
  test [service]          Test connectivity through the sidecar
  vault create            Create an encrypted vault file
  vault add <service>     Add/update a secret in the vault
  vault remove <service>  Remove a secret from the vault
  vault list              List secrets in the vault (names only)
  migrate                 Import secrets from .env files into Keyhole store
  safe-repo               Ensure .gitignore covers secret files
  help                    Show this help
  version                 Show version

Options:
  --config <path>         Path to keyhole.yaml (default: ./keyhole.yaml)
  --dry-run               (migrate) Show what would be imported without writing
  --no-cleanup            (migrate) Import secrets but don't modify source files
`);
}

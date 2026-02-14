export interface SecretStore {
  /** Retrieve a secret by reference name */
  get(ref: string): Promise<string>;

  /** Store a secret */
  set(ref: string, value: string, passphrase?: string): Promise<void>;

  /** Delete a secret */
  delete(ref: string, passphrase?: string): Promise<void>;

  /** List all stored secret reference names */
  list(): Promise<string[]>;

  /** Check if a secret exists without retrieving it */
  has(ref: string): Promise<boolean>;
}

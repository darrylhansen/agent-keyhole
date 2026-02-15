export const MIN_SECRET_LENGTH = 8;

export class SecretRegistry {
  /** O(1) lookup set for exact matches */
  private exactSet: Set<string>;
  /** Array of all variants for substring scanning */
  private allVariants: string[];
  /** Length of shortest entry, for skipping short strings in substring scan */
  private minLength: number;

  constructor(secrets: Map<string, string>, placeholders: Set<string>) {
    this.exactSet = new Set();
    this.allVariants = [];
    this.minLength = Infinity;

    for (const secret of secrets.values()) {
      if (secret.length < MIN_SECRET_LENGTH) continue;
      if (placeholders.has(secret)) continue;

      const variants = [
        secret,
        Buffer.from(secret).toString('base64'),
        encodeURIComponent(secret),
      ];

      // Deduplicate (URL-encoded may equal plain for ASCII-only secrets)
      const uniqueVariants = [...new Set(variants)];

      for (const v of uniqueVariants) {
        this.exactSet.add(v);
        this.allVariants.push(v);
        this.minLength = Math.min(this.minLength, v.length);
      }
    }

    if (this.minLength === Infinity) this.minLength = MIN_SECRET_LENGTH;
  }

  hasExact(value: string): boolean {
    return this.exactSet.has(value);
  }

  findSubstring(value: string): string | null {
    if (value.length < this.minLength) return null;
    for (const variant of this.allVariants) {
      if (value.includes(variant)) return variant;
    }
    return null;
  }

  replaceAllSubstrings(
    value: string,
    marker: string
  ): { result: string; replaced: boolean } {
    if (value.length < this.minLength) {
      return { result: value, replaced: false };
    }

    let result = value;
    let replaced = false;

    for (const variant of this.allVariants) {
      if (result.includes(variant)) {
        result = result.replaceAll(variant, marker);
        replaced = true;
      }
    }

    return { result, replaced };
  }

  getAllVariants(): string[] {
    return this.allVariants;
  }

  getMinLength(): number {
    return this.minLength;
  }

  isEmpty(): boolean {
    return this.exactSet.size === 0;
  }
}

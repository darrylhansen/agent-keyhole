import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  redactJsonPaths,
  parseJsonPath,
  maskJsonPaths,
} from '../../src/sidecar/json-path-redactor.js';
import { REDACTION_MARKER } from '../helpers/fixtures.js';

describe('json-path-redactor', () => {
  describe('redactJsonPaths', () => {
    it('$.token redacts top-level key', () => {
      const obj = { token: 'secret-value', name: 'test' };
      const result = redactJsonPaths(obj, ['$.token']);
      assert.equal(result, true);
      assert.equal(obj.token, REDACTION_MARKER);
      assert.equal(obj.name, 'test');
    });

    it('$.credentials.access_token redacts nested value', () => {
      const obj = { credentials: { access_token: 'secret', type: 'bearer' } };
      const result = redactJsonPaths(obj, ['$.credentials.access_token']);
      assert.equal(result, true);
      assert.equal(obj.credentials.access_token, REDACTION_MARKER);
      assert.equal(obj.credentials.type, 'bearer');
    });

    it('$.data[*].secret redacts all array elements', () => {
      const obj = {
        data: [
          { name: 'a', secret: 'one' },
          { name: 'b', secret: 'two' },
          { name: 'c', secret: 'three' },
        ],
      };
      const result = redactJsonPaths(obj, ['$.data[*].secret']);
      assert.equal(result, true);
      for (const item of obj.data) {
        assert.equal(item.secret, REDACTION_MARKER);
        assert.ok(item.name); // name preserved
      }
    });

    it('missing path causes no crash, no redaction', () => {
      const obj = { name: 'test' };
      const result = redactJsonPaths(obj, ['$.nonexistent.path']);
      assert.equal(result, false);
      assert.equal(obj.name, 'test');
    });

    it('non-object target causes no crash', () => {
      assert.equal(redactJsonPaths(null, ['$.token']), false);
      assert.equal(redactJsonPaths(undefined, ['$.token']), false);
      assert.equal(redactJsonPaths(42, ['$.token']), false);
    });

    it('non-string leaf value (number, boolean) is skipped', () => {
      const obj = { count: 42, active: true, name: 'test' };
      const result = redactJsonPaths(obj, ['$.count', '$.active']);
      assert.equal(result, false);
      assert.equal(obj.count, 42);
      assert.equal(obj.active, true);
    });
  });

  describe('parseJsonPath', () => {
    it('parses simple path', () => {
      assert.deepEqual(parseJsonPath('$.token'), ['token']);
    });

    it('parses nested path', () => {
      assert.deepEqual(parseJsonPath('$.credentials.access_token'), [
        'credentials',
        'access_token',
      ]);
    });

    it('parses wildcard path', () => {
      assert.deepEqual(parseJsonPath('$.data[*].secret'), [
        'data',
        '*',
        'secret',
      ]);
    });

    it('handles path without $. prefix', () => {
      assert.deepEqual(parseJsonPath('$token'), ['token']);
    });
  });

  describe('maskJsonPaths', () => {
    it('non-JSON body is returned unmodified', () => {
      const body = 'not valid json {{}}';
      const result = maskJsonPaths(body, ['$.token']);
      assert.equal(result.body, body);
      assert.equal(result.redacted, false);
    });

    it('valid JSON body with matching path is redacted', () => {
      const body = JSON.stringify({ token: 'secret', name: 'test' });
      const result = maskJsonPaths(body, ['$.token']);
      assert.equal(result.redacted, true);
      const parsed = JSON.parse(result.body);
      assert.equal(parsed.token, REDACTION_MARKER);
      assert.equal(parsed.name, 'test');
    });

    it('valid JSON body with no matching path returns unchanged', () => {
      const body = JSON.stringify({ name: 'test' });
      const result = maskJsonPaths(body, ['$.token']);
      assert.equal(result.body, body);
      assert.equal(result.redacted, false);
    });
  });
});

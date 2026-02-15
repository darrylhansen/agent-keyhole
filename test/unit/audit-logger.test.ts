import { describe, it, mock, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { AuditLogger, sanitizePathForLog } from '../../src/sidecar/audit-logger.js';
import type { ServiceConfig } from '../../src/config/schema.js';

describe('AuditLogger', () => {
  describe('JSON format output', () => {
    it('outputs JSON with correct fields', () => {
      const writeMock = mock.method(process.stderr, 'write', () => true);
      const logger = new AuditLogger({ level: 'info', output: 'stderr' });

      logger.info('test.event', { service: 'github', method: 'GET', path: '/user' });

      assert.ok(writeMock.mock.calls.length > 0);
      const output = writeMock.mock.calls[0].arguments[0] as string;
      const parsed = JSON.parse(output.trim());

      assert.equal(parsed.level, 'info');
      assert.equal(parsed.event, 'test.event');
      assert.equal(parsed.service, 'github');
      assert.equal(parsed.method, 'GET');
      assert.ok(parsed.timestamp);

      writeMock.mock.restore();
    });
  });

  describe('log level filtering', () => {
    it('debug hidden at info level', () => {
      const writeMock = mock.method(process.stderr, 'write', () => true);
      const logger = new AuditLogger({ level: 'info', output: 'stderr' });

      logger.debug('should.be.hidden');
      assert.equal(writeMock.mock.calls.length, 0);

      writeMock.mock.restore();
    });

    it('warn visible at info level', () => {
      const writeMock = mock.method(process.stderr, 'write', () => true);
      const logger = new AuditLogger({ level: 'info', output: 'stderr' });

      logger.warn('should.be.visible');
      assert.equal(writeMock.mock.calls.length, 1);

      writeMock.mock.restore();
    });

    it('info visible at debug level', () => {
      const writeMock = mock.method(process.stderr, 'write', () => true);
      const logger = new AuditLogger({ level: 'debug', output: 'stderr' });

      logger.info('visible.at.debug');
      assert.equal(writeMock.mock.calls.length, 1);

      writeMock.mock.restore();
    });

    it('error visible at error level', () => {
      const writeMock = mock.method(process.stderr, 'write', () => true);
      const logger = new AuditLogger({ level: 'error', output: 'stderr' });

      logger.error('visible.error');
      assert.equal(writeMock.mock.calls.length, 1);
      logger.warn('hidden.warn');
      assert.equal(writeMock.mock.calls.length, 1);

      writeMock.mock.restore();
    });
  });

  describe('stdout output mode', () => {
    it('writes to stdout when configured', () => {
      const writeMock = mock.method(process.stdout, 'write', () => true);
      const logger = new AuditLogger({ level: 'info', output: 'stdout' });

      logger.info('stdout.test');
      assert.ok(writeMock.mock.calls.length > 0);

      writeMock.mock.restore();
    });
  });
});

describe('sanitizePathForLog', () => {
  const queryParamService: ServiceConfig = {
    domains: ['maps.googleapis.com'],
    auth: {
      type: 'query_param',
      param_name: 'key',
      secret_ref: 'maps-key',
    },
    base_url: 'https://maps.googleapis.com',
  };

  const bearerService: ServiceConfig = {
    domains: ['api.github.com'],
    auth: {
      type: 'bearer',
      secret_ref: 'github-token',
    },
    base_url: 'https://api.github.com',
  };

  it('strips query_param secret from path', () => {
    const result = sanitizePathForLog(
      '/geocode/json?address=NYC&key=REAL_SECRET',
      queryParamService
    );
    assert.ok(!result.includes('REAL_SECRET'));
    assert.ok(!result.includes('key='));
    assert.ok(result.includes('address=NYC'));
  });

  it('preserves non-secret query params', () => {
    const result = sanitizePathForLog(
      '/geocode/json?address=NYC&format=json&key=SECRET',
      queryParamService
    );
    assert.ok(result.includes('address=NYC'));
    assert.ok(result.includes('format=json'));
  });

  it('non-query_param service path is unchanged', () => {
    const result = sanitizePathForLog('/user?tab=repos', bearerService);
    assert.equal(result, '/user?tab=repos');
  });

  it('path without query string unchanged for query_param service', () => {
    const result = sanitizePathForLog('/geocode/json', queryParamService);
    assert.equal(result, '/geocode/json');
  });
});

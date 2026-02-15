import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { isBodyBinary } from '../../src/client/binary-detect.js';

describe('binary-detect', () => {
  describe('text Content-Types', () => {
    it('text/html returns false', () => {
      assert.equal(isBodyBinary('text/html', Buffer.from('hello')), false);
    });

    it('application/json returns false', () => {
      assert.equal(isBodyBinary('application/json', Buffer.from('{}')), false);
    });

    it('application/json; charset=utf-8 returns false', () => {
      assert.equal(
        isBodyBinary('application/json; charset=utf-8', Buffer.from('{}')),
        false
      );
    });

    it('application/xml returns false', () => {
      assert.equal(isBodyBinary('application/xml', Buffer.from('<x/>')), false);
    });
  });

  describe('binary Content-Types', () => {
    it('image/png returns true', () => {
      assert.equal(isBodyBinary('image/png', Buffer.from([0x89, 0x50])), true);
    });

    it('application/octet-stream returns true', () => {
      assert.equal(
        isBodyBinary('application/octet-stream', Buffer.from([0x00])),
        true
      );
    });

    it('audio/mp3 returns true', () => {
      assert.equal(isBodyBinary('audio/mp3', Buffer.from([0xff, 0xfb])), true);
    });
  });

  describe('byte sniffing (no Content-Type)', () => {
    it('buffer with null bytes returns true', () => {
      const buf = Buffer.from([0x48, 0x65, 0x6c, 0x00, 0x6f]);
      assert.equal(isBodyBinary(undefined, buf), true);
    });

    it('buffer with only printable chars returns false', () => {
      const buf = Buffer.from('Hello, world! 123', 'utf-8');
      assert.equal(isBodyBinary(undefined, buf), false);
    });

    it('buffer with control chars returns true', () => {
      const buf = Buffer.from([0x48, 0x02, 0x65]); // 0x02 is STX control char
      assert.equal(isBodyBinary(undefined, buf), true);
    });
  });

  describe('string body', () => {
    it('string body always returns false regardless of content', () => {
      assert.equal(isBodyBinary(undefined, 'any string'), false);
      assert.equal(isBodyBinary(undefined, '\x00\x01\x02'), false);
    });
  });

  describe('edge cases', () => {
    it('no body returns false', () => {
      assert.equal(isBodyBinary(undefined, undefined), false);
    });

    it('empty buffer returns false', () => {
      assert.equal(isBodyBinary(undefined, Buffer.alloc(0)), false);
    });
  });
});

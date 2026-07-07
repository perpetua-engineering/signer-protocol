import { canonicalize, parseProfile } from '../src/jcs.js';

describe('CSP1 canonical JSON (RFC 8785 restricted profile)', () => {
  test('sorts object keys by UTF-16 code units', () => {
    expect(canonicalize({ b: 2, a: 1, aa: 3, A: 0 })).toBe('{"A":0,"a":1,"aa":3,"b":2}');
  });

  test('nested structures and arrays', () => {
    expect(canonicalize({ z: [true, false, 'x'], a: { k: 7 } })).toBe(
      '{"a":{"k":7},"z":[true,false,"x"]}',
    );
  });

  test('string escaping matches the Swift implementation', () => {
    expect(canonicalize({ s: 'quote" backslash\\ newline\n tab\t bell unicode→' })).toBe(
      '{"s":"quote\\" backslash\\\\ newline\\n tab\\t bell\\u0007 unicode→"}',
    );
  });

  test('integers serialize without decoration', () => {
    expect(canonicalize(0)).toBe('0');
    expect(canonicalize(-42)).toBe('-42');
    expect(canonicalize(9007199254740991)).toBe('9007199254740991');
  });

  test('rejects null', () => {
    expect(() => parseProfile('{"a":null}')).toThrow();
  });

  test('rejects fractional numbers', () => {
    expect(() => parseProfile('{"a":1.5}')).toThrow();
  });

  test('accepts integral doubles as integers', () => {
    expect(canonicalize(parseProfile('{"a":7.0}'))).toBe('{"a":7}');
  });

  test('rejects magnitudes beyond 2^53−1', () => {
    expect(() => parseProfile('{"a":9007199254740992}')).toThrow();
  });

  test('round trip is stable', () => {
    const canonical = canonicalize(parseProfile('{\n "b" : 1, "a" : ["x", true] }'));
    expect(canonical).toBe('{"a":["x",true],"b":1}');
    expect(canonicalize(parseProfile(canonical))).toBe(canonical);
  });
});

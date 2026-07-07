//
// RFC 8785 (JCS) canonical JSON for the CSP1 restricted profile
// (docs at https://cryptograph.watch/signer-protocol §4.3):
//   - numbers are integers with |n| ≤ 2^53 − 1
//   - no null values
//   - strings are well-formed UTF-8
// Under these restrictions JCS reduces to: UTF-8, object keys sorted by
// UTF-16 code units, no whitespace, plain integer serialization, and the
// standard two-character escapes.
//

export type CSPValue =
  | string
  | number
  | boolean
  | CSPValue[]
  | { [key: string]: CSPValue };

export const MAX_INTEGER_MAGNITUDE = 9_007_199_254_740_991; // 2^53 − 1
const MAX_NESTING_DEPTH = 32;

export function assertProfile(value: unknown, depth = 0): asserts value is CSPValue {
  if (depth > MAX_NESTING_DEPTH) throw new Error('CSP1: nesting too deep');
  if (value === null || value === undefined) {
    throw new Error('CSP1: null is not allowed');
  }
  switch (typeof value) {
    case 'string':
    case 'boolean':
      return;
    case 'number':
      if (!Number.isInteger(value) || Math.abs(value) > MAX_INTEGER_MAGNITUDE) {
        throw new Error(`CSP1: number out of profile: ${value}`);
      }
      return;
    case 'object':
      if (Array.isArray(value)) {
        for (const element of value) assertProfile(element, depth + 1);
        return;
      }
      for (const element of Object.values(value as Record<string, unknown>)) {
        assertProfile(element, depth + 1);
      }
      return;
    default:
      throw new Error(`CSP1: unsupported value type ${typeof value}`);
  }
}

function escapeString(text: string): string {
  let output = '"';
  for (const char of text) {
    const code = char.codePointAt(0)!;
    switch (char) {
      case '"': output += '\\"'; break;
      case '\\': output += '\\\\'; break;
      case '\b': output += '\\b'; break;
      case '\t': output += '\\t'; break;
      case '\n': output += '\\n'; break;
      case '\f': output += '\\f'; break;
      case '\r': output += '\\r'; break;
      default:
        if (code < 0x20) {
          output += '\\u' + code.toString(16).padStart(4, '0');
        } else {
          output += char;
        }
    }
  }
  return output + '"';
}

/// Sort comparator over UTF-16 code units (RFC 8785 §3.2.3).
function compareKeys(a: string, b: string): number {
  const length = Math.min(a.length, b.length);
  for (let i = 0; i < length; i += 1) {
    const delta = a.charCodeAt(i) - b.charCodeAt(i);
    if (delta !== 0) return delta;
  }
  return a.length - b.length;
}

export function canonicalize(value: CSPValue): string {
  assertProfile(value);
  return serialize(value);
}

function serialize(value: CSPValue): string {
  if (typeof value === 'string') return escapeString(value);
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') return String(value);
  if (Array.isArray(value)) return '[' + value.map(serialize).join(',') + ']';
  const keys = Object.keys(value).sort(compareKeys);
  return (
    '{' + keys.map((key) => escapeString(key) + ':' + serialize(value[key]!)).join(',') + '}'
  );
}

/// Parses JSON text, enforcing the restricted profile. Fractional numbers
/// with integral values (e.g. 7.0) survive JSON.parse as integers, matching
/// the Swift implementation.
export function parseProfile(text: string): CSPValue {
  const raw: unknown = JSON.parse(text);
  assertProfile(raw);
  return raw;
}

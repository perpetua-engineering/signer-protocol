//
//  CSPCanonicalJSON.swift
//  Cryptograph
//
//  Restricted JSON model + RFC 8785 (JCS) canonical serialization for the
//  Cryptograph Signer Protocol (CSP) v1. See docs/SIGNER_PROTOCOL.md §4.3.
//
//  The CSP1 profile restricts JSON so every conforming serializer can produce
//  the canonical form: numbers are integers with |n| ≤ 2^53−1, strings are
//  well-formed UTF-8, and null is not used. Envelope-level fields are further
//  restricted to non-negative integers by CSPEnvelope validation.
//

import Foundation

public enum CSPCanonicalJSONError: Error, Equatable {
    case notAnObject
    case unsupportedNumber(String)
    case nullNotAllowed
    case unsupportedValue(String)
    case nestingTooDeep
    case invalidJSON(String)
}

/// A JSON value in the CSP1 restricted profile.
public indirect enum CSPJSON: Equatable {
    case string(String)
    case int(Int64)
    case bool(Bool)
    case array([CSPJSON])
    case object([String: CSPJSON])

    /// Largest magnitude allowed for integers (2^53 − 1), so all values are
    /// exactly representable in every JSON implementation including JavaScript.
    public static let maxIntegerMagnitude: Int64 = 9_007_199_254_740_991

    private static let maxNestingDepth = 32

    // MARK: - Accessors

    public var stringValue: String? {
        if case .string(let value) = self { return value }
        return nil
    }

    public var intValue: Int64? {
        if case .int(let value) = self { return value }
        return nil
    }

    public var boolValue: Bool? {
        if case .bool(let value) = self { return value }
        return nil
    }

    public var arrayValue: [CSPJSON]? {
        if case .array(let value) = self { return value }
        return nil
    }

    public var objectValue: [String: CSPJSON]? {
        if case .object(let value) = self { return value }
        return nil
    }

    // MARK: - Parsing

    /// Parses JSON bytes into the restricted model. Rejects nulls, fractional
    /// numbers, and integers beyond ±(2^53 − 1).
    public static func parse(_ data: Data) throws -> CSPJSON {
        let raw: Any
        do {
            raw = try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])
        } catch {
            throw CSPCanonicalJSONError.invalidJSON(String(describing: error))
        }
        return try from(foundation: raw, depth: 0)
    }

    /// Parses JSON bytes that must be a top-level object.
    public static func parseObject(_ data: Data) throws -> [String: CSPJSON] {
        guard let object = try parse(data).objectValue else {
            throw CSPCanonicalJSONError.notAnObject
        }
        return object
    }

    static func from(foundation value: Any, depth: Int) throws -> CSPJSON {
        guard depth <= maxNestingDepth else { throw CSPCanonicalJSONError.nestingTooDeep }

        switch value {
        case let string as String:
            return .string(string)
        case let number as NSNumber:
            if CFGetTypeID(number) == CFBooleanGetTypeID() {
                return .bool(number.boolValue)
            }
            return .int(try integer(from: number))
        case let array as [Any]:
            return .array(try array.map { try from(foundation: $0, depth: depth + 1) })
        case let dictionary as [String: Any]:
            var object: [String: CSPJSON] = [:]
            object.reserveCapacity(dictionary.count)
            for (key, element) in dictionary {
                object[key] = try from(foundation: element, depth: depth + 1)
            }
            return .object(object)
        case is NSNull:
            throw CSPCanonicalJSONError.nullNotAllowed
        default:
            throw CSPCanonicalJSONError.unsupportedValue(String(describing: type(of: value)))
        }
    }

    private static func integer(from number: NSNumber) throws -> Int64 {
        // Accept integral doubles (e.g. a peer serialized 7 as 7.0): JCS
        // canonicalizes both to "7", so the signed bytes are identical.
        let objCType = String(cString: number.objCType)
        if objCType == "d" || objCType == "f" {
            let doubleValue = number.doubleValue
            guard doubleValue.rounded() == doubleValue,
                  doubleValue >= -Double(maxIntegerMagnitude),
                  doubleValue <= Double(maxIntegerMagnitude) else {
                throw CSPCanonicalJSONError.unsupportedNumber(number.stringValue)
            }
            return Int64(doubleValue)
        }
        let intValue = number.int64Value
        // Reject UInt64 overflow wrap and out-of-profile magnitudes.
        guard NSNumber(value: intValue) == number,
              intValue >= -maxIntegerMagnitude,
              intValue <= maxIntegerMagnitude else {
            throw CSPCanonicalJSONError.unsupportedNumber(number.stringValue)
        }
        return intValue
    }

    // MARK: - Canonical serialization (RFC 8785)

    /// Serializes to canonical bytes: UTF-8, object keys sorted by UTF-16 code
    /// units, no whitespace, integers without sign/exponent/leading zeros,
    /// two-character escapes where JSON defines them.
    public func canonicalData() -> Data {
        var output = String()
        appendCanonical(to: &output)
        return Data(output.utf8)
    }

    private func appendCanonical(to output: inout String) {
        switch self {
        case .string(let value):
            Self.appendEscaped(value, to: &output)
        case .int(let value):
            output.append(String(value))
        case .bool(let value):
            output.append(value ? "true" : "false")
        case .array(let values):
            output.append("[")
            for (index, value) in values.enumerated() {
                if index > 0 { output.append(",") }
                value.appendCanonical(to: &output)
            }
            output.append("]")
        case .object(let object):
            output.append("{")
            let sortedKeys = object.keys.sorted { lhs, rhs in
                lhs.utf16.lexicographicallyPrecedes(rhs.utf16)
            }
            for (index, key) in sortedKeys.enumerated() {
                if index > 0 { output.append(",") }
                Self.appendEscaped(key, to: &output)
                output.append(":")
                object[key]?.appendCanonical(to: &output)
            }
            output.append("}")
        }
    }

    private static func appendEscaped(_ string: String, to output: inout String) {
        output.append("\"")
        for scalar in string.unicodeScalars {
            switch scalar {
            case "\"": output.append("\\\"")
            case "\\": output.append("\\\\")
            case "\u{08}": output.append("\\b")
            case "\u{09}": output.append("\\t")
            case "\u{0A}": output.append("\\n")
            case "\u{0C}": output.append("\\f")
            case "\u{0D}": output.append("\\r")
            default:
                if scalar.value < 0x20 {
                    output.append(String(format: "\\u%04x", scalar.value))
                } else {
                    output.unicodeScalars.append(scalar)
                }
            }
        }
        output.append("\"")
    }
}

// MARK: - Codable bridge

extension CSPJSON: Codable {
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let bool = try? container.decode(Bool.self) {
            self = .bool(bool)
        } else if let int = try? container.decode(Int64.self) {
            guard int >= -Self.maxIntegerMagnitude,
                  int <= Self.maxIntegerMagnitude else {
                throw DecodingError.dataCorruptedError(
                    in: container, debugDescription: "Integer outside CSP1 profile")
            }
            self = .int(int)
        } else if let string = try? container.decode(String.self) {
            self = .string(string)
        } else if let array = try? container.decode([CSPJSON].self) {
            self = .array(array)
        } else if let object = try? container.decode([String: CSPJSON].self) {
            self = .object(object)
        } else {
            throw DecodingError.dataCorruptedError(
                in: container, debugDescription: "Value outside CSP1 profile")
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .string(let value): try container.encode(value)
        case .int(let value): try container.encode(value)
        case .bool(let value): try container.encode(value)
        case .array(let value): try container.encode(value)
        case .object(let value): try container.encode(value)
        }
    }
}

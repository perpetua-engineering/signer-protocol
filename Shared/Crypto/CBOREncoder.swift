//
//  CBOREncoder.swift
//  Cryptograph
//
//  Minimal CBOR encoder/decoder for encrypted recovery payloads.
//  Supports only: uint, tstr (text), bstr (bytes), map.
//  RFC 8949: Concise Binary Object Representation (CBOR)
//

import Foundation

// MARK: - CBOR Value Type

/// A CBOR value that can be encoded/decoded.
enum CBORValue: Equatable {
    case uint(UInt64)
    case negInt(UInt64)    // CBOR negative int: encodes value (-1 - n), e.g. negInt(6) = -7
    case tstr(String)
    case bstr(Data)
    case bool(Bool)
    case map([String: CBORValue])
    case intMap([(Int, CBORValue)])  // Integer-keyed map (preserves insertion order for CTAP2)
    case array([CBORValue])
    case double(Double)

    static func == (lhs: CBORValue, rhs: CBORValue) -> Bool {
        switch (lhs, rhs) {
        case (.uint(let a), .uint(let b)): return a == b
        case (.negInt(let a), .negInt(let b)): return a == b
        case (.tstr(let a), .tstr(let b)): return a == b
        case (.bstr(let a), .bstr(let b)): return a == b
        case (.bool(let a), .bool(let b)): return a == b
        case (.map(let a), .map(let b)): return a == b
        case (.intMap(let a), .intMap(let b)):
            guard a.count == b.count else { return false }
            return zip(a, b).allSatisfy { $0.0 == $1.0 && $0.1 == $1.1 }
        case (.array(let a), .array(let b)): return a == b
        case (.double(let a), .double(let b)): return a == b
        default: return false
        }
    }
}

// MARK: - CBOR Major Types

private enum CBORMajorType: UInt8 {
    case unsignedInt = 0  // 0x00-0x1f
    case negativeInt = 1  // 0x20-0x3f
    case byteString = 2   // 0x40-0x5f
    case textString = 3   // 0x60-0x7f
    case array = 4        // 0x80-0x9f
    case map = 5          // 0xa0-0xbf
    case tag = 6          // 0xc0-0xdf (not supported)
    case simple = 7       // 0xe0-0xff (bool, float)
}

// MARK: - Encoder

/// Encodes a text-keyed dictionary to CBOR bytes.
func cborEncode(_ map: [String: CBORValue]) -> Data {
    var encoder = CBOREncoder()
    encoder.encodeMap(map)
    return encoder.data
}

/// Encodes a single CBORValue to bytes.
func cborEncodeValue(_ value: CBORValue) -> Data {
    var encoder = CBOREncoder()
    encoder.encode(value)
    return encoder.data
}

private struct CBOREncoder {
    var data = Data()

    mutating func encode(_ value: CBORValue) {
        switch value {
        case .uint(let n):
            encodeUInt(n)
        case .negInt(let n):
            encodeNegInt(n)
        case .tstr(let s):
            encodeTextString(s)
        case .bstr(let d):
            encodeByteString(d)
        case .bool(let b):
            encodeBool(b)
        case .map(let m):
            encodeMap(m)
        case .intMap(let pairs):
            encodeIntMap(pairs)
        case .array(let a):
            encodeArray(a)
        case .double(let d):
            encodeDouble(d)
        }
    }

    mutating func encodeUInt(_ value: UInt64) {
        encodeTypeAndLength(majorType: .unsignedInt, length: value)
    }

    mutating func encodeNegInt(_ value: UInt64) {
        // CBOR negative int encodes (-1 - n), so negInt(6) → -7
        encodeTypeAndLength(majorType: .negativeInt, length: value)
    }

    mutating func encodeBool(_ value: Bool) {
        // CBOR simple values: false = 0xf4 (major 7, additional 20), true = 0xf5 (major 7, additional 21)
        data.append(value ? 0xf5 : 0xf4)
    }

    mutating func encodeTextString(_ string: String) {
        let utf8 = Data(string.utf8)
        encodeTypeAndLength(majorType: .textString, length: UInt64(utf8.count))
        data.append(utf8)
    }

    mutating func encodeByteString(_ bytes: Data) {
        encodeTypeAndLength(majorType: .byteString, length: UInt64(bytes.count))
        data.append(bytes)
    }

    mutating func encodeMap(_ map: [String: CBORValue]) {
        // Sort keys for deterministic encoding (RFC 8949 §4.2.1)
        let sortedKeys = map.keys.sorted()
        encodeTypeAndLength(majorType: .map, length: UInt64(map.count))
        for key in sortedKeys {
            encodeTextString(key)
            // Key is guaranteed present — sourced from map.keys above
            if let value = map[key] {
                encode(value)
            }
        }
    }

    mutating func encodeIntMap(_ pairs: [(Int, CBORValue)]) {
        encodeTypeAndLength(majorType: .map, length: UInt64(pairs.count))
        for (key, value) in pairs {
            if key >= 0 {
                encodeUInt(UInt64(key))
            } else {
                // CBOR negative: encode (-1 - key)
                encodeNegInt(UInt64(-1 - key))
            }
            encode(value)
        }
    }

    mutating func encodeArray(_ array: [CBORValue]) {
        encodeTypeAndLength(majorType: .array, length: UInt64(array.count))
        for element in array {
            encode(element)
        }
    }

    mutating func encodeDouble(_ value: Double) {
        // CBOR float64 (major type 7, additional info 27)
        data.append(0xfb)  // 7 << 5 | 27
        appendBigEndian(value.bitPattern)
    }

    private mutating func encodeTypeAndLength(majorType: CBORMajorType, length: UInt64) {
        let typeShift = majorType.rawValue << 5

        if length < 24 {
            data.append(typeShift | UInt8(length))
        } else if length <= UInt8.max {
            data.append(typeShift | 24)
            data.append(UInt8(length))
        } else if length <= UInt16.max {
            data.append(typeShift | 25)
            appendBigEndian(UInt16(length))
        } else if length <= UInt32.max {
            data.append(typeShift | 26)
            appendBigEndian(UInt32(length))
        } else {
            data.append(typeShift | 27)
            appendBigEndian(length)
        }
    }

    private mutating func appendBigEndian<T: FixedWidthInteger>(_ value: T) {
        withUnsafeBytes(of: value.bigEndian) { data.append(contentsOf: $0) }
    }
}

// MARK: - Decoder

enum CBORDecodingError: Error {
    case unexpectedEnd
    case unsupportedType(UInt8)
    case invalidUTF8
    case expectedMap
    case expectedTextKey
}

/// Decodes CBOR bytes to a text-keyed dictionary.
func cborDecode(_ data: Data) throws -> [String: CBORValue] {
    var decoder = CBORDecoder(data: data)
    let value = try decoder.decode()
    guard case .map(let map) = value else {
        throw CBORDecodingError.expectedMap
    }
    return map
}

/// Decodes CBOR bytes to a generic CBORValue.
func cborDecodeValue(_ data: Data) throws -> CBORValue {
    var decoder = CBORDecoder(data: data)
    return try decoder.decode()
}

/// Decodes CBOR bytes and returns how many bytes were consumed.
func cborDecodeWithLength(_ data: Data) throws -> (CBORValue, Int) {
    var decoder = CBORDecoder(data: data)
    let value = try decoder.decode()
    return (value, decoder.offset)
}

struct CBORDecoder {
    let data: Data
    var offset: Int = 0

    var remaining: Int { data.count - offset }

    mutating func decode() throws -> CBORValue {
        guard offset < data.count else {
            throw CBORDecodingError.unexpectedEnd
        }

        let initialByte = data[offset]
        offset += 1

        let majorType = initialByte >> 5
        let additionalInfo = initialByte & 0x1f

        switch majorType {
        case CBORMajorType.unsignedInt.rawValue:
            let value = try decodeLength(additionalInfo)
            return .uint(value)

        case CBORMajorType.negativeInt.rawValue:
            let value = try decodeLength(additionalInfo)
            return .negInt(value)

        case CBORMajorType.byteString.rawValue:
            let length = try decodeLength(additionalInfo)
            let bytes = try readBytes(Int(length))
            return .bstr(bytes)

        case CBORMajorType.textString.rawValue:
            let length = try decodeLength(additionalInfo)
            let bytes = try readBytes(Int(length))
            guard let string = String(data: bytes, encoding: .utf8) else {
                throw CBORDecodingError.invalidUTF8
            }
            return .tstr(string)

        case CBORMajorType.map.rawValue:
            let count = try decodeLength(additionalInfo)
            // Try text-keyed first; fall back to int-keyed for CTAP2 responses
            var textMap = [String: CBORValue]()
            var intPairs = [(Int, CBORValue)]()
            var hasIntKey = false
            for _ in 0..<count {
                let key = try decode()
                let value = try decode()
                switch key {
                case .tstr(let keyString):
                    textMap[keyString] = value
                case .uint(let n):
                    intPairs.append((Int(n), value))
                    hasIntKey = true
                case .negInt(let n):
                    intPairs.append((-1 - Int(n), value))
                    hasIntKey = true
                default:
                    throw CBORDecodingError.expectedTextKey
                }
            }
            if hasIntKey {
                return .intMap(intPairs)
            }
            return .map(textMap)

        case CBORMajorType.array.rawValue:
            let count = try decodeLength(additionalInfo)
            var array = [CBORValue]()
            for _ in 0..<count {
                let element = try decode()
                array.append(element)
            }
            return .array(array)

        case CBORMajorType.simple.rawValue:
            // Handle booleans: false = 20, true = 21
            if additionalInfo == 20 { return .bool(false) }
            if additionalInfo == 21 { return .bool(true) }
            // Handle float64 (additional info 27)
            if additionalInfo == 27 {
                let bits = try readBigEndian(UInt64.self)
                return .double(Double(bitPattern: bits))
            }
            throw CBORDecodingError.unsupportedType(initialByte)

        default:
            throw CBORDecodingError.unsupportedType(initialByte)
        }
    }

    private mutating func decodeLength(_ additionalInfo: UInt8) throws -> UInt64 {
        if additionalInfo < 24 {
            return UInt64(additionalInfo)
        } else if additionalInfo == 24 {
            return UInt64(try readByte())
        } else if additionalInfo == 25 {
            return UInt64(try readBigEndian(UInt16.self))
        } else if additionalInfo == 26 {
            return UInt64(try readBigEndian(UInt32.self))
        } else if additionalInfo == 27 {
            return try readBigEndian(UInt64.self)
        } else {
            throw CBORDecodingError.unsupportedType(additionalInfo)
        }
    }

    private mutating func readByte() throws -> UInt8 {
        guard remaining >= 1 else { throw CBORDecodingError.unexpectedEnd }
        let byte = data[offset]
        offset += 1
        return byte
    }

    private mutating func readBytes(_ count: Int) throws -> Data {
        guard remaining >= count else { throw CBORDecodingError.unexpectedEnd }
        let bytes = data[offset..<offset + count]
        offset += count
        return Data(bytes)
    }

    private mutating func readBigEndian<T: FixedWidthInteger>(_ type: T.Type) throws -> T {
        let size = MemoryLayout<T>.size
        guard remaining >= size else { throw CBORDecodingError.unexpectedEnd }
        // Read bytes and construct integer manually to avoid alignment issues
        var value: T = 0
        for i in 0..<size {
            value = (value << 8) | T(data[offset + i])
        }
        offset += size
        return value
    }
}

// MARK: - Base64URL

extension Data {
    /// Encode to base64url (RFC 4648 §5) - no padding.
    var base64URLEncoded: String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Decode from base64url (RFC 4648 §5).
    init?(base64URLEncoded string: String) {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        // Add padding if needed
        let paddingLength = (4 - base64.count % 4) % 4
        base64 += String(repeating: "=", count: paddingLength)

        self.init(base64Encoded: base64)
    }
}

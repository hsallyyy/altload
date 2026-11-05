import Compression
import Foundation

/// Reads an IPA's bundle ID straight from the ZIP without unpacking it: only the central
/// directory and Payload/<App>.app/Info.plist are read. Inside LiveContainer this is
/// what stops an IPA from Files from being installed over LiveContainer itself.
enum IPAInfo {
    static func bundleIdentifier(of ipa: URL) -> String? {
        guard let data = infoPlist(of: ipa),
              let info = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any]
        else { return nil }
        return info["CFBundleIdentifier"] as? String
    }

    private static func infoPlist(of ipa: URL) -> Data? {
        guard let handle = try? FileHandle(forReadingFrom: ipa) else { return nil }
        defer { try? handle.close() }
        guard let fileSize = try? handle.seekToEnd() else { return nil }

        // The end-of-central-directory record is the last 22 bytes, plus a comment of up
        // to 64 KB.
        let tailLength = min(fileSize, 22 + 0xFFFF)
        guard let tail = read(handle, at: fileSize - tailLength, count: Int(tailLength)),
              let end = lastSignature(0x0605_4B50, in: tail) else { return nil }
        let directorySize = tail.uint32(at: end + 12)
        let directoryOffset = tail.uint32(at: end + 16)
        // ZIP64 (archives over 4 GB) puts 0xFFFFFFFF here. LiveContainer is nowhere near that.
        guard directorySize != 0xFFFF_FFFF, directoryOffset != 0xFFFF_FFFF,
              let directory = read(handle, at: UInt64(directoryOffset), count: Int(directorySize)) else { return nil }

        var cursor = 0
        while cursor + 46 <= directory.count, directory.uint32(at: cursor) == 0x0201_4B50 {
            let method = directory.uint16(at: cursor + 10)
            let compressedSize = Int(directory.uint32(at: cursor + 20))
            let size = Int(directory.uint32(at: cursor + 24))
            let nameLength = Int(directory.uint16(at: cursor + 28))
            let next = cursor + 46 + nameLength
                + Int(directory.uint16(at: cursor + 30)) + Int(directory.uint16(at: cursor + 32))
            let localOffset = UInt64(directory.uint32(at: cursor + 42))
            guard cursor + 46 + nameLength <= directory.count else { return nil }
            let name = String(decoding: directory[(cursor + 46)..<(cursor + 46 + nameLength)], as: UTF8.self)
            cursor = next

            // Payload/Name.app/Info.plist, not an extension's deeper down.
            let parts = name.split(separator: "/", omittingEmptySubsequences: false)
            guard parts.count == 3, parts[0] == "Payload", parts[1].hasSuffix(".app"), parts[2] == "Info.plist" else {
                continue
            }
            guard size > 0, size < 4 << 20,
                  let header = read(handle, at: localOffset, count: 30), header.uint32(at: 0) == 0x0403_4B50
            else { return nil }
            let dataOffset = localOffset + 30 + UInt64(header.uint16(at: 26)) + UInt64(header.uint16(at: 28))
            guard let stored = read(handle, at: dataOffset, count: compressedSize) else { return nil }
            switch method {
            case 0: return stored
            case 8: return inflate(stored, size: size)
            default: return nil
            }
        }
        return nil
    }

    private static func read(_ handle: FileHandle, at offset: UInt64, count: Int) -> Data? {
        guard count > 0, (try? handle.seek(toOffset: offset)) != nil,
              let data = try? handle.read(upToCount: count), data.count == count else { return nil }
        return data
    }

    private static func lastSignature(_ signature: UInt32, in data: Data) -> Int? {
        guard data.count >= 22 else { return nil }
        for index in stride(from: data.count - 22, through: 0, by: -1) where data.uint32(at: index) == signature {
            return index
        }
        return nil
    }

    /// ZIP's method 8 is raw DEFLATE, which is what COMPRESSION_ZLIB decodes (no zlib header).
    private static func inflate(_ data: Data, size: Int) -> Data? {
        var output = Data(count: size)
        let written = output.withUnsafeMutableBytes { (out: UnsafeMutableRawBufferPointer) -> Int in
            data.withUnsafeBytes { (input: UnsafeRawBufferPointer) -> Int in
                guard let destination = out.bindMemory(to: UInt8.self).baseAddress,
                      let source = input.bindMemory(to: UInt8.self).baseAddress else { return 0 }
                return compression_decode_buffer(destination, size, source, input.count, nil, COMPRESSION_ZLIB)
            }
        }
        return written == size ? output : nil
    }
}

private extension Data {
    /// Little-endian, as everything in a ZIP is. Callers check the bounds first.
    func uint16(at offset: Int) -> UInt16 {
        let i = startIndex + offset
        return UInt16(self[i]) | UInt16(self[i + 1]) << 8
    }

    func uint32(at offset: Int) -> UInt32 {
        UInt32(uint16(at: offset)) | UInt32(uint16(at: offset + 2)) << 16
    }
}

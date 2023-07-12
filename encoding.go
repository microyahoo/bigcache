package bigcache

import (
	"encoding/binary"
)

const (
	timestampSizeInBytes = 8                                                       // Number of bytes used for timestamp
	hashSizeInBytes      = 8                                                       // Number of bytes used for hash
	keySizeInBytes       = 2                                                       // Number of bytes used for size of entry key
	headersSizeInBytes   = timestampSizeInBytes + hashSizeInBytes + keySizeInBytes // Number of bytes used for all headers
)

// ringbuffer entry 格式为：
// +------------+-------------+-------------+-------------+-----------------+
// | timestamp  |     hash    |  key length |     key     |      entry      |
// +------------+-------------+-------------+-------------+-----------------+
// |     8      |      8      |      2      |   len(key)  |     len(entry)  |
// +------------+-------------+-------------+-------------+-----------------+
// |               entry header             |          entry data           |
// +------------+-------------+-------------+-------------+-----------------+
func wrapEntry(timestamp uint64, hash uint64, key string, entry []byte, buffer *[]byte) []byte {
	keyLength := len(key)
	blobLength := len(entry) + headersSizeInBytes + keyLength

	if blobLength > len(*buffer) {
		*buffer = make([]byte, blobLength)
	}
	blob := *buffer

	binary.LittleEndian.PutUint64(blob, timestamp)                                                // 8 字节的时间戳
	binary.LittleEndian.PutUint64(blob[timestampSizeInBytes:], hash)                              // 8 字节的 hash 值
	binary.LittleEndian.PutUint16(blob[timestampSizeInBytes+hashSizeInBytes:], uint16(keyLength)) // 2 个字节的 key 长度
	copy(blob[headersSizeInBytes:], key)
	copy(blob[headersSizeInBytes+keyLength:], entry)

	return blob[:blobLength]
}

func appendToWrappedEntry(timestamp uint64, wrappedEntry []byte, entry []byte, buffer *[]byte) []byte {
	blobLength := len(wrappedEntry) + len(entry)
	if blobLength > len(*buffer) {
		*buffer = make([]byte, blobLength)
	}

	blob := *buffer

	binary.LittleEndian.PutUint64(blob, timestamp)
	copy(blob[timestampSizeInBytes:], wrappedEntry[timestampSizeInBytes:])
	copy(blob[len(wrappedEntry):], entry)

	return blob[:blobLength]
}

func readEntry(data []byte) []byte { // 从 entry 中读取 value
	length := binary.LittleEndian.Uint16(data[timestampSizeInBytes+hashSizeInBytes:])

	// copy on read
	dst := make([]byte, len(data)-int(headersSizeInBytes+length))
	copy(dst, data[headersSizeInBytes+length:])

	return dst
}

func readTimestampFromEntry(data []byte) uint64 {
	return binary.LittleEndian.Uint64(data)
}

func readKeyFromEntry(data []byte) string { // 从 entry 中读取 key
	length := binary.LittleEndian.Uint16(data[timestampSizeInBytes+hashSizeInBytes:])

	// copy on read
	dst := make([]byte, length)
	copy(dst, data[headersSizeInBytes:headersSizeInBytes+length])

	return bytesToString(dst)
}

func compareKeyFromEntry(data []byte, key string) bool {
	length := binary.LittleEndian.Uint16(data[timestampSizeInBytes+hashSizeInBytes:])

	return bytesToString(data[headersSizeInBytes:headersSizeInBytes+length]) == key
}

func readHashFromEntry(data []byte) uint64 { // 读取 hash 值
	return binary.LittleEndian.Uint64(data[timestampSizeInBytes:])
}

func resetHashFromEntry(data []byte) { // 将 entry 的 hash 值设置为 0
	binary.LittleEndian.PutUint64(data[timestampSizeInBytes:], 0)
}

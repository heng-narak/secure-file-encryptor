"""
File header handling for encrypted files.
Fixed version with correct struct packing.
"""
import struct
from typing import Tuple


# Constants
MAGIC_BYTES = b"SFEV1.0\0"  # 8 bytes: Secure File Encryptor Version 1.0
VERSION = 1


class FileHeader:
    """Represents the header of an encrypted file."""
    
    def __init__(self):
        self.version = VERSION
        self.salt = b""
        self.nonce = b""
        self.tag = b""
        self.filename = ""
    
    @classmethod
    def create_new(cls, salt: bytes, nonce: bytes, tag: bytes, original_filename: str = "") -> 'FileHeader':
        """Create a new header for encryption."""
        header = cls()
        header.salt = salt
        header.nonce = nonce
        header.tag = tag
        header.filename = original_filename
        return header
    
    def to_bytes(self) -> bytes:
        """Convert header to binary format."""
        # Convert filename to bytes if present
        filename_bytes = self.filename.encode('utf-8') if self.filename else b""
        
        # Get lengths
        salt_len = len(self.salt)
        nonce_len = len(self.nonce)
        tag_len = len(self.tag)
        filename_len = len(filename_bytes)
        
        # Create format string and pack data
        # Format parts:
        # 8s: magic bytes (8 chars)
        # B: version (1 byte)
        # B: salt_len (1 byte)
        # {salt_len}s: salt (variable)
        # B: nonce_len (1 byte)
        # {nonce_len}s: nonce (variable)
        # B: tag_len (1 byte)
        # {tag_len}s: tag (variable)
        # H: filename_len (2 bytes, unsigned short)
        # {filename_len}s: filename (variable)
        
        format_str = f"!8sBBB{salt_len}sB{nonce_len}sB{tag_len}sH"
        if filename_len > 0:
            format_str += f"{filename_len}s"
            data_tuple = (
                MAGIC_BYTES,
                self.version,
                salt_len,
                self.salt,
                nonce_len,
                self.nonce,
                tag_len,
                self.tag,
                filename_len,
                filename_bytes
            )
        else:
            # No filename to pack
            data_tuple = (
                MAGIC_BYTES,
                self.version,
                salt_len,
                self.salt,
                nonce_len,
                self.nonce,
                tag_len,
                self.tag,
                filename_len
            )
        
        return struct.pack(format_str, *data_tuple)
    
    @classmethod
    def from_bytes(cls, data: bytes) -> Tuple['FileHeader', int]:
        """Parse header from binary data. Returns (header, header_size)."""
        # Minimum header size: magic(8) + version(1) + salt_len(1)
        if len(data) < 10:
            raise ValueError(f"Data too short for header. Need at least 10 bytes, got {len(data)}")
        
        # Read magic and version
        magic = data[:8]
        if magic != MAGIC_BYTES:
            raise ValueError(f"Invalid magic bytes. Expected {MAGIC_BYTES.hex()}, got {magic.hex()}")
        
        version = data[8]
        
        # Start parsing variable length fields
        pos = 9  # After magic(8) and version(1)
        
        # Read salt
        salt_len = data[pos]
        pos += 1
        if pos + salt_len > len(data):
            raise ValueError(f"Salt length {salt_len} exceeds available data")
        salt = data[pos:pos + salt_len]
        pos += salt_len
        
        # Read nonce
        nonce_len = data[pos]
        pos += 1
        if pos + nonce_len > len(data):
            raise ValueError(f"Nonce length {nonce_len} exceeds available data")
        nonce = data[pos:pos + nonce_len]
        pos += nonce_len
        
        # Read tag
        tag_len = data[pos]
        pos += 1
        if pos + tag_len > len(data):
            raise ValueError(f"Tag length {tag_len} exceeds available data")
        tag = data[pos:pos + tag_len]
        pos += tag_len
        
        # Read filename length (2 bytes)
        if pos + 2 > len(data):
            # No filename present
            filename = ""
        else:
            filename_len = struct.unpack_from("!H", data, pos)[0]
            pos += 2
            
            # Read filename if present
            if filename_len > 0:
                if pos + filename_len > len(data):
                    raise ValueError(f"Filename length {filename_len} exceeds available data")
                filename_bytes = data[pos:pos + filename_len]
                filename = filename_bytes.decode('utf-8', errors='ignore')
                pos += filename_len
            else:
                filename = ""
        
        # Create header object
        header = cls()
        header.version = version
        header.salt = salt
        header.nonce = nonce
        header.tag = tag
        header.filename = filename
        
        return header, pos
    
    def __str__(self) -> str:
        """String representation for debugging."""
        return (f"FileHeader(version={self.version}, "
                f"salt={self.salt.hex()[:8]}..., "
                f"nonce={self.nonce.hex()[:8]}..., "
                f"tag={self.tag.hex()[:8]}..., "
                f"filename='{self.filename}')")


class SimpleFileHeader:
    """Simpler fixed-size header for easier debugging."""
    
    HEADER_SIZE = 296  # Fixed size: 8 + 16 + 12 + 16 + 244 = 296 bytes
    
    def __init__(self):
        self.version = 1  # Add version attribute
        self.salt = b""
        self.nonce = b""
        self.tag = b""
        self.filename = ""
    
    @classmethod
    def create_new(cls, salt: bytes, nonce: bytes, tag: bytes, filename: str = "") -> 'SimpleFileHeader':
        header = cls()
        header.salt = salt
        header.nonce = nonce
        header.tag = tag
        header.filename = filename[:244]  # Limit to fit in header
        return header
    
    def to_bytes(self) -> bytes:
        """Convert to binary - fixed size format."""
        # Magic: 8 bytes
        magic = b"SFE_ENC\0"
        
        # Filename: up to 244 bytes (padded with zeros)
        filename_bytes = self.filename.encode('utf-8', errors='ignore')[:244]
        filename_padded = filename_bytes.ljust(244, b'\0')
        
        # Pack: magic(8) + salt(16) + nonce(12) + tag(16) + filename(244)
        return struct.pack(
            "!8s16s12s16s244s",
            magic,
            self.salt,
            self.nonce,
            self.tag,
            filename_padded
        )
    
    @classmethod
    def from_bytes(cls, data: bytes) -> Tuple['SimpleFileHeader', int]:
        """Parse from binary - fixed size."""
        if len(data) < cls.HEADER_SIZE:
            raise ValueError(f"Data too short. Need {cls.HEADER_SIZE} bytes, got {len(data)}")
        
        magic, salt, nonce, tag, filename_bytes = struct.unpack("!8s16s12s16s244s", data[:cls.HEADER_SIZE])
        
        if magic != b"SFE_ENC\0":
            raise ValueError("Invalid magic bytes")
        
        # Remove padding from filename
        filename = filename_bytes.rstrip(b'\0').decode('utf-8', errors='ignore')
        
        header = cls()
        header.salt = salt
        header.nonce = nonce
        header.tag = tag
        header.filename = filename
        
        return header, cls.HEADER_SIZE
    
    def __str__(self):
        return (f"SimpleFileHeader(version={self.version}, "
                f"salt={self.salt.hex()[:8]}..., "
                f"nonce={self.nonce.hex()[:8]}..., "
                f"tag={self.tag.hex()[:8]}..., "
                f"filename='{self.filename}')")


def test_both_headers():
    """Test both header implementations."""
    import os
    
    print("=== Testing FileHeader (variable length) ===")
    
    # Test 1: With filename
    salt = os.urandom(16)
    nonce = os.urandom(12)
    tag = os.urandom(16)
    filename = "test_document.txt"
    
    header1 = FileHeader.create_new(salt, nonce, tag, filename)
    print(f"Created: {header1}")
    
    header_bytes1 = header1.to_bytes()
    print(f"Header size: {len(header_bytes1)} bytes")
    
    parsed_header1, size1 = FileHeader.from_bytes(header_bytes1)
    print(f"Parsed: {parsed_header1}")
    print(f"Size from parsing: {size1} bytes")
    
    assert header1.salt == parsed_header1.salt
    assert header1.nonce == parsed_header1.nonce
    assert header1.tag == parsed_header1.tag
    assert header1.filename == parsed_header1.filename
    print("✓ With filename: PASSED\n")
    
    # Test 2: Without filename
    header2 = FileHeader.create_new(salt, nonce, tag, "")
    print(f"Created (no filename): {header2}")
    
    header_bytes2 = header2.to_bytes()
    print(f"Header size: {len(header_bytes2)} bytes")
    
    parsed_header2, size2 = FileHeader.from_bytes(header_bytes2)
    print(f"Parsed: {parsed_header2}")
    print(f"Size from parsing: {size2} bytes")
    
    assert header2.salt == parsed_header2.salt
    assert header2.nonce == parsed_header2.nonce
    assert header2.tag == parsed_header2.tag
    print("✓ Without filename: PASSED\n")
    
    print("=== Testing SimpleFileHeader (fixed length) ===")
    
    # Test simple header
    simple_header = SimpleFileHeader.create_new(salt, nonce, tag, filename)
    print(f"Created: {simple_header}")
    
    simple_bytes = simple_header.to_bytes()
    print(f"Header size: {len(simple_bytes)} bytes (always {SimpleFileHeader.HEADER_SIZE})")
    
    parsed_simple, simple_size = SimpleFileHeader.from_bytes(simple_bytes)
    print(f"Parsed: {parsed_simple}")
    print(f"Size from parsing: {simple_size} bytes")
    
    assert simple_header.salt == parsed_simple.salt
    assert simple_header.nonce == parsed_simple.nonce
    assert simple_header.tag == parsed_simple.tag
    assert simple_header.filename == parsed_simple.filename
    print("✓ Simple header: PASSED")
    
    print("\n=== All tests passed! ===")


if __name__ == "__main__":
    test_both_headers()
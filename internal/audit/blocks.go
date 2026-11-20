// Compressed files in blocks: each MiB of a rotated file is its own gzip
// member (RFC 1952 allows several in one file; gzip -d and Go's reader read
// them as one stream), and each member's header carries its compressed
// length in an extra subfield, as BGZF does for genomics files. A reader
// walks the headers to index the members and decompresses only the member
// an offset falls in, so a search reads an archived file backwards, as it
// reads a plain one, holding one member in memory.

package audit

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strings"
)

// blockSize is the uncompressed size of one member: big enough that the
// lost 32 KiB of deflate history at each boundary costs little ratio.
const blockSize = 1 << 20

// blockField is the extra subfield naming a member's compressed length:
// ID "AW", 4 data bytes, little-endian; Go's writer puts it at bytes 16-20.
var blockField = []byte{'A', 'W', 4, 0, 0, 0, 0, 0}

// writeBlocks compresses in to out, one member per blockSize, the first
// with header's name, comment and time, and returns the bytes written.
func writeBlocks(out io.Writer, in io.Reader, header gzip.Header) (int64, error) {
	data := make([]byte, blockSize)
	var member bytes.Buffer
	zw := gzip.NewWriter(&member)
	var total int64
	for first := true; ; first = false {
		n, err := io.ReadFull(in, data)
		if n == 0 && !first {
			return total, ignoreShort(err)
		}
		member.Reset()
		zw.Reset(&member)
		zw.Extra = bytes.Clone(blockField)
		if first {
			zw.Name, zw.Comment, zw.ModTime = header.Name, header.Comment, header.ModTime
		}
		if _, werr := zw.Write(data[:n]); werr != nil {
			return total, werr
		}
		if cerr := zw.Close(); cerr != nil {
			return total, cerr
		}
		packed := member.Bytes()
		length := uint64(len(packed))
		if length > math.MaxUint32 {
			return total, errors.New("a compressed block exceeds 4 GiB")
		}
		binary.LittleEndian.PutUint32(packed[16:20], uint32(length))
		if _, werr := out.Write(packed); werr != nil {
			return total, werr
		}
		total += int64(len(packed))
		if err != nil {
			return total, ignoreShort(err)
		}
	}
}

// ignoreShort drops the end-of-input errors of a last, short read.
func ignoreShort(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return nil
	}
	return err
}

// block is one member: where it is in the file and in the content.
type block struct{ at, length, start, size int64 }

// packedLog reads a block-compressed file at any offset of its content.
type packedLog struct {
	file   *os.File
	blocks []block
	size   int64
	cached int // the member in data, -1 for none
	data   []byte
}

// openPacked indexes the members of the compressed file at path.
func openPacked(path string) (*packedLog, error) {
	file, err := OpenShared(path)
	if err != nil {
		return nil, err
	}
	p := &packedLog{file: file, cached: -1}
	if err := p.index(); err != nil {
		return nil, errors.Join(fmt.Errorf("%s: %w", path, err), file.Close())
	}
	return p, nil
}

// index reads each member's header and trailer.
func (p *packedLog) index() error {
	info, err := p.file.Stat()
	if err != nil {
		return err
	}
	head := make([]byte, 20)
	for at := int64(0); at < info.Size(); {
		if _, err := p.file.ReadAt(head, at); err != nil {
			return err
		}
		if head[0] != 0x1f || head[1] != 0x8b || head[3]&4 == 0 || !bytes.Equal(head[12:16], blockField[:4]) {
			return errors.New("not a block-compressed audit file")
		}
		length := int64(binary.LittleEndian.Uint32(head[16:20]))
		if length < 28 || at+length > info.Size() {
			return errors.New("a compressed block's length is out of range")
		}
		if _, err := p.file.ReadAt(head[:4], at+length-4); err != nil {
			return err
		}
		size := int64(binary.LittleEndian.Uint32(head[:4]))
		if size > blockSize {
			return errors.New("a compressed block holds more than one block's content")
		}
		p.blocks = append(p.blocks, block{at: at, length: length, start: p.size, size: size})
		p.size += size
		at += length
	}
	return nil
}

// ReadAt reads the content at off, decompressing the members it spans.
func (p *packedLog) ReadAt(b []byte, off int64) (int, error) {
	read := 0
	for read < len(b) {
		at := off + int64(read)
		if at >= p.size {
			return read, io.EOF
		}
		i := sort.Search(len(p.blocks), func(i int) bool { return p.blocks[i].start+p.blocks[i].size > at })
		if err := p.load(i); err != nil {
			return read, err
		}
		read += copy(b[read:], p.data[at-p.blocks[i].start:])
	}
	return read, nil
}

// load decompresses member i into data.
func (p *packedLog) load(i int) error {
	if p.cached == i {
		return nil
	}
	b := p.blocks[i]
	zr, err := gzip.NewReader(io.NewSectionReader(p.file, b.at, b.length))
	if err != nil {
		return err
	}
	zr.Multistream(false)
	p.data = p.data[:0]
	buffer := bytes.NewBuffer(p.data)
	// Read one byte past the trailer's size, so a block that expands
	// further (a changed file) is caught without decompressing it all.
	if _, err := io.CopyN(buffer, zr, b.size+1); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	p.data, p.cached = buffer.Bytes(), i
	if int64(len(p.data)) != b.size {
		p.cached = -1
		return errors.New("a compressed block's size does not match its trailer")
	}
	return nil
}

// End is the content's size; a compressed file has no zero tail.
func (p *packedLog) End() (int64, error) { return p.size, nil }

func (p *packedLog) Close() error { return p.file.Close() }

// LogReader reads one audit file at any offset of its content; End is where
// its content ends.
type LogReader interface {
	io.ReaderAt
	io.Closer
	End() (int64, error)
}

// plainLog is an uncompressed file, whose content ends at End.
type plainLog struct{ *os.File }

func (p plainLog) End() (int64, error) { return End(p.File) }

// OpenLog opens an audit file, plain or compressed, for reading at offsets.
func OpenLog(path string) (LogReader, error) {
	if strings.HasSuffix(path, packedSuffix) {
		return openPacked(path)
	}
	file, err := OpenShared(path)
	if err != nil {
		return nil, err
	}
	return plainLog{file}, nil
}

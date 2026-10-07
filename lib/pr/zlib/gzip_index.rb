# frozen_string_literal: true

require 'digest'
require_relative 'gzipfile_errors'

module Zlib

  # Zlib::GzipIndex builds a random-access index over a gzip file so that
  # individual uncompressed ranges can be read repeatedly without inflating
  # the whole file each time.
  #
  # The index is a list of checkpoints taken at deflate block boundaries.
  # Each checkpoint stores the compressed offset, the number of bits already
  # consumed from the byte at that offset, and the 32KB history window --
  # everything inflate needs to resume decompression from that point. The
  # source file does not need to be split into independent gzip members; the
  # saved history window makes checkpoints inside a single monolithic deflate
  # stream usable as restart points. Concatenated gzip members are supported
  # as well, and every member starts a fresh checkpoint with an empty window.
  #
  # An index is bound to the identity of the source file (size, mtime and a
  # SHA-256 digest computed while building). A Reader refuses to use an index
  # whose source file has changed.
  #
  # CRC verification is reported at two distinct scopes:
  #
  # * Reader#verify inflates the entire file and checks the CRC32 and ISIZE
  #   of every member, returning an IntegrityReport with full_file? == true.
  # * Reader#read only verifies the members it happens to cover completely;
  #   its ReadReport always has full_file? == false and never claims whole
  #   file integrity from a partial read.
  #
  # Example:
  #
  #   index = Zlib::GzipIndex.build('big.gz', span: 1 << 20)
  #   index.save('big.gz.idx')
  #
  #   index = Zlib::GzipIndex.load('big.gz.idx')
  #   reader = index.reader_for('big.gz')
  #   chunk = reader.read(10_000_000, 4096)
  #   reader.last_report.full_file? # => false (partial read)
  #   reader.verify.ok?             # => true  (full CRC pass)
  #
  class GzipIndex
    WINDOW_SIZE    = 1 << 15 # deflate history window (32KB)
    DEFAULT_SPAN   = 1 << 20 # uncompressed bytes between checkpoints
    INPUT_CHUNK    = 1 << 16
    OUTPUT_CHUNK   = 1 << 15
    FORMAT_MAGIC   = 'pr-zlib-gzip-index'
    FORMAT_VERSION = 1

    # gzip header flag bits (RFC 1952)
    FLAG_TEXT       = 1
    FLAG_HCRC       = 2
    FLAG_EXTRA      = 4
    FLAG_NAME       = 8
    FLAG_COMMENT    = 16
    RESERVED_FLAGS  = 0xe0

    # Raised when the source file no longer matches the identity recorded
    # in the index.
    class SourceChangedError < GzipFile::Error; end

    # Raised when the gzip file (or a serialized index) is malformed.
    class FormatError < GzipFile::Error; end

    # Raised when the gzip file ends prematurely.
    class TruncatedError < GzipFile::Error; end

    # Compressed offset + bit position + history window needed to resume
    # inflate at +out_offset+ uncompressed bytes.
    Checkpoint = Struct.new(:in_offset, :bits, :out_offset, :window)

    # Start of one gzip member: +in_offset+ is the first byte of its raw
    # deflate stream, +out_offset+ its first uncompressed byte.
    Member = Struct.new(:in_offset, :out_offset)

    attr_reader :span, :checkpoints, :members, :uncompressed_size,
                :source_size, :source_mtime, :source_sha256

    def initialize(span: DEFAULT_SPAN)
      @span = span
      @checkpoints = []
      @members = []
      @uncompressed_size = 0
      @source_size = nil
      @source_mtime = nil
      @source_sha256 = nil
    end

    # Build an index over the gzip file at +path+. +span+ is the target
    # number of uncompressed bytes between checkpoints; smaller spans give
    # faster random access at the cost of a larger index. The whole file is
    # inflated once and every member's CRC32 and ISIZE are verified, so a
    # corrupt file raises GzipFile::CRCError or GzipFile::LengthError here.
    def self.build(path, span: DEFAULT_SPAN)
      index = new(span: span)
      index.send(:build!, path)
      index
    end

    # Serialize the index to +path+.
    def save(path)
      payload = {
        'magic'             => FORMAT_MAGIC,
        'version'           => FORMAT_VERSION,
        'span'              => @span,
        'uncompressed_size' => @uncompressed_size,
        'source_size'       => @source_size,
        'source_mtime'      => @source_mtime,
        'source_sha256'     => @source_sha256,
        'members'           => @members.map { |m| [m.in_offset, m.out_offset] },
        'checkpoints'       => @checkpoints.map { |c| [c.in_offset, c.bits, c.out_offset, c.window] }
      }
      File.open(path, 'wb') { |f| f.write(Marshal.dump(payload)) }
      path
    end

    # Load an index previously written with #save.
    def self.load(path)
      payload = Marshal.load(File.binread(path)) rescue nil
      unless payload.is_a?(Hash) && payload['magic'] == FORMAT_MAGIC
        raise FormatError, "#{path} is not a #{FORMAT_MAGIC} file"
      end
      unless payload['version'] == FORMAT_VERSION
        raise FormatError, "unsupported index format version #{payload['version'].inspect}"
      end

      index = new(span: payload['span'])
      index.send(:restore!,
        uncompressed_size: payload['uncompressed_size'],
        source_size:       payload['source_size'],
        source_mtime:      payload['source_mtime'],
        source_sha256:     payload['source_sha256'],
        members:           payload['members'].map { |i, o| Member.new(i, o) },
        checkpoints:       payload['checkpoints'].map { |i, b, o, w| Checkpoint.new(i, b, o, w) }
      )
      index
    end

    # True when the file at +path+ no longer matches the identity recorded
    # in the index. The cheap check compares size and mtime; with
    # +strict: true+ the SHA-256 of the whole file is recomputed and
    # compared, which also catches content changes that preserve size and
    # mtime.
    def source_changed?(path, strict: false)
      stat = File.stat(path)
      return true if stat.size != @source_size
      return true if stat.mtime != @source_mtime
      return true if strict && Digest::SHA256.file(path).hexdigest != @source_sha256

      false
    end

    # Raise SourceChangedError when the index does not match +path+.
    def verify_source!(path, strict: false)
      if source_changed?(path, strict: strict)
        raise SourceChangedError, "index was built for different contents: #{path}"
      end

      true
    end

    # Open a random-access reader for +path+ using this index. Raises
    # SourceChangedError when the file changed since the index was built.
    def reader_for(path, strict: false)
      verify_source!(path, strict: strict)
      Reader.new(path, self)
    end

    # Index of the member containing uncompressed +offset+.
    def member_index_for(offset)
      idx = @members.bsearch_index { |m| m.out_offset > offset }
      return nil if @members.empty?
      return @members.size - 1 if idx.nil?

      idx.zero? ? 0 : idx - 1
    end

    # The latest checkpoint at or before uncompressed +offset+.
    def checkpoint_for(offset)
      idx = @checkpoints.bsearch_index { |c| c.out_offset > offset }
      return @checkpoints.last if idx.nil?
      return @checkpoints.first if idx.zero?

      @checkpoints[idx - 1]
    end

    # Parse one gzip member header from +reader+ (a ChunkReader). Returns the
    # header length in bytes, or nil at a clean end of file between members.
    def self.parse_member_header(reader)
      start = reader.pos
      sig = reader.read(2)
      return nil if sig.empty?

      unless sig == "\x1f\x8b".b
        raise FormatError, 'not in gzip format (bad magic or trailing garbage)'
      end

      fixed = reader.read(8)
      raise TruncatedError, 'truncated gzip header' if fixed.bytesize < 8

      method = fixed.getbyte(0)
      flags  = fixed.getbyte(1)
      unless method == 8
        raise FormatError, "unknown compression method #{method}"
      end
      unless (flags & RESERVED_FLAGS).zero?
        raise FormatError, "unknown gzip header flags #{flags & RESERVED_FLAGS}"
      end

      if (flags & FLAG_EXTRA) != 0
        xlen_bytes = reader.read(2)
        raise TruncatedError, 'truncated FEXTRA field' if xlen_bytes.bytesize < 2

        xlen = xlen_bytes.unpack1('v')
        raise TruncatedError, 'truncated FEXTRA field' if reader.read(xlen).bytesize < xlen
      end
      skip_cstring(reader, 'FNAME') if (flags & FLAG_NAME) != 0
      skip_cstring(reader, 'FCOMMENT') if (flags & FLAG_COMMENT) != 0
      if (flags & FLAG_HCRC) != 0 && reader.read(2).bytesize < 2
        raise TruncatedError, 'truncated FHCRC field'
      end

      reader.pos - start
    end

    def self.skip_cstring(reader, field)
      loop do
        byte = reader.read(1)
        raise TruncatedError, "truncated #{field} field" if byte.empty?
        break if byte == "\0"
      end
    end
    private_class_method :skip_cstring

    # Read and check the 8-byte gzip trailer (CRC32 + ISIZE) of a member.
    # Raises GzipFile::CRCError or GzipFile::LengthError on mismatch.
    def self.verify_member_trailer(reader, crc, member_out, member_idx)
      trailer = reader.read(8)
      raise TruncatedError, 'truncated gzip trailer' if trailer.bytesize < 8

      expected_crc, isize = trailer.unpack('VV')
      if expected_crc != crc
        raise GzipFile::CRCError, "invalid compressed data -- crc error (member #{member_idx})"
      end
      if isize != member_out % (1 << 32)
        raise GzipFile::LengthError, "invalid compressed data -- length error (member #{member_idx})"
      end

      true
    end

    # A fresh raw-deflate inflate stream (no zlib/gzip wrapper).
    def self.new_raw_stream
      strm = Rbzlib::Z_stream.new
      err = Rbzlib.inflateInit2(strm, -Rbzlib::MAX_WBITS)
      unless err == Rbzlib::Z_OK
        raise GzipFile::Error, "inflateInit2 failed: #{Rbzlib.zError(err)}"
      end

      strm
    end

    # Byte source with pushback and absolute position tracking. When a
    # Digest is given, every byte read from the underlying IO is hashed
    # exactly once, in file order (pushed-back bytes are not rehashed).
    class ChunkReader
      attr_reader :pos

      def initialize(io, digest = nil)
        @io = io
        @digest = digest
        @pending = ''.b
        @pos = 0
      end

      # Read up to +num+ bytes; fewer only at end of file.
      def read(num)
        out = @pending.slice!(0, num) || ''.b
        while out.bytesize < num
          more = @io.read(num - out.bytesize)
          break if more.nil? || more.empty?

          @digest.update(more) if @digest
          out << more
        end
        @pos += out.bytesize
        out
      end

      # Push bytes back so the next read returns them again.
      def unread(bytes)
        return if bytes.nil? || bytes.empty?

        @pending = bytes + @pending
        @pos -= bytes.bytesize
      end

      def seek(pos)
        @pending = ''.b
        @io.seek(pos)
        @pos = pos
      end
    end

    private

    def restore!(uncompressed_size:, source_size:, source_mtime:,
                 source_sha256:, members:, checkpoints:)
      @uncompressed_size = uncompressed_size
      @source_size = source_size
      @source_mtime = source_mtime
      @source_sha256 = source_sha256
      @members = members
      @checkpoints = checkpoints
      self
    end

    def build!(path)
      stat = File.stat(path)
      digest = Digest::SHA256.new
      total_out = 0

      File.open(path, 'rb') do |io|
        reader = ChunkReader.new(io, digest)
        loop do
          header = self.class.parse_member_header(reader)
          break if header.nil?

          @members << Member.new(reader.pos, total_out)
          @checkpoints << Checkpoint.new(reader.pos, 0, total_out, ''.b)

          crc, member_out, leftover = inflate_member(reader, total_out)
          reader.unread(leftover)
          self.class.verify_member_trailer(reader, crc, member_out, @members.size - 1)
          total_out += member_out
        end
      end

      @uncompressed_size = total_out
      @source_size = stat.size
      @source_mtime = stat.mtime
      @source_sha256 = digest.hexdigest
      self
    end

    # Inflate one raw deflate member from +reader+, recording checkpoints at
    # deflate block boundaries at least +span+ uncompressed bytes apart.
    # Returns [crc32, uncompressed_size, leftover] where leftover is the
    # unconsumed tail of the last input chunk (start of the gzip trailer).
    def inflate_member(reader, member_out_start)
      strm = self.class.new_raw_stream
      window = ''.b
      crc = 0
      member_out = 0
      last_checkpoint_out = member_out_start
      fed = nil

      begin
        loop do
          if strm.avail_in.nil? || strm.avail_in.zero?
            chunk = reader.read(INPUT_CHUNK)
            if chunk.empty?
              raise TruncatedError, 'unexpected end of file inside deflate stream'
            end

            fed = chunk
            strm.next_in = Rbzlib::Bytef.new(chunk)
            strm.avail_in = chunk.bytesize
          end

          out_buf = 0.chr * OUTPUT_CHUNK
          strm.next_out = Rbzlib::Bytef.new(out_buf)
          strm.avail_out = OUTPUT_CHUNK
          ret = Rbzlib.inflate(strm, Rbzlib::Z_BLOCK)
          produced = OUTPUT_CHUNK - strm.avail_out

          if produced.positive?
            out = out_buf.byteslice(0, produced)
            crc = Rbzlib.crc32(crc, out)
            window += out
            window = window[-WINDOW_SIZE..-1] if window.bytesize > WINDOW_SIZE
            member_out += produced
          end

          break if ret == Rbzlib::Z_STREAM_END

          unless ret == Rbzlib::Z_OK || ret == Rbzlib::Z_BUF_ERROR
            raise GzipFile::Error, "inflate failed: #{Rbzlib.zError(ret)} (#{strm.msg})"
          end
          if ret == Rbzlib::Z_BUF_ERROR && !strm.avail_in.zero?
            raise GzipFile::Error, 'inflate made no progress'
          end

          data_type = strm.data_type
          total_out = member_out_start + member_out
          if (data_type & 128) != 0 && (data_type & 64).zero? &&
              total_out - last_checkpoint_out >= @span
            @checkpoints << Checkpoint.new(
              @members.last.in_offset + strm.total_in,
              data_type & 7,
              total_out,
              window.dup
            )
            last_checkpoint_out = total_out
          end
        end
      ensure
        Rbzlib.inflateEnd(strm)
      end

      leftover = strm.avail_in.positive? ? fed.byteslice(fed.bytesize - strm.avail_in, strm.avail_in) : ''.b
      [crc, member_out, leftover]
    end
  end
end

# frozen_string_literal: true

require_relative 'errors'

module Zlib
  # Random-access index for gzip files.
  #
  # Large gzip files that must be read repeatedly at a handful of
  # uncompressed offsets can be indexed once and then sampled cheaply:
  #
  #   index = Zlib::GzipIndex.build('big.gz', span: 1 << 20)
  #   index.save('big.gz.gzi')
  #
  #   index = Zlib::GzipIndex.load('big.gz.gzi')
  #   index.open('big.gz') do |gz|
  #     gz.read_at(1_000_000, 4096) # bytes at uncompressed offset 1_000_000
  #   end
  #
  # Building the index inflates the whole file once and records a checkpoint
  # at a deflate block boundary every +span+ uncompressed bytes (or more).
  # A checkpoint stores the compressed and uncompressed offsets, the bit
  # position inside the last compressed byte, and the preceding 32KB of
  # uncompressed history, which is everything inflate needs to resume
  # mid-stream.  The source file does not have to be split into independent
  # gzip members for this to work (concatenated members are handled too).
  #
  # An index is bound to the identity of its source file (size, mtime and a
  # content fingerprint).  If the file changes after the index was built,
  # the index refuses to operate on it and raises StaleIndexError.
  #
  # CRC verification is reported in two strictly separated scopes:
  #
  # * GzipIndex#verification covers the whole stream.  It is only
  #   +verified+ when every gzip member was inflated to its trailer and the
  #   stored CRC32 and ISIZE matched (done while building, or on demand via
  #   GzipIndex#verify!).
  # * GzipIndex::Reader#last_verification covers only the region returned
  #   by the most recent read_at.  A partial read never claims that the
  #   whole gzip stream passed its CRC check.
  class GzipIndex
    # Size of the deflate sliding history window.
    WINDOW_SIZE = 1 << 15

    # Default distance between checkpoints, in uncompressed bytes.
    DEFAULT_SPAN = 1 << 20

    # I/O and inflate buffer size used while building and reading.
    CHUNK_SIZE = 1 << 16

    # Number of head/tail bytes included in the source fingerprint.
    FINGERPRINT_BYTES = 1 << 16

    # Version of the Marshal payload written by #save.
    FORMAT_VERSION = 1

    # windowBits for a gzip-wrapped stream (15 + 16).
    GZIP_WBITS = 31

    # windowBits for a raw deflate stream.
    RAW_WBITS = -15

    # Generic index error.
    class Error < Zlib::Error; end

    # Raised when the gzip file no longer matches the index.
    class StaleIndexError < Error; end

    # Raised when a serialized index cannot be understood.
    class CorruptIndexError < Error; end

    # A single checkpoint.  +output+ and +input+ are the uncompressed and
    # compressed offsets of a deflate block boundary, +bits+ is the number
    # of bits of the byte at +input - 1+ that belong to the block starting
    # at the boundary, and +window+ holds the uncompressed bytes (at most
    # WINDOW_SIZE of them) immediately preceding +output+.
    Point = Struct.new(:output, :input, :bits, :window)

    attr_reader :span, :points, :content_size, :content_crc32, :members,
                :source

    # Build an index for the gzip file at +path+.  Inflates the whole file
    # once, verifying the CRC32 and ISIZE of every member, and records a
    # checkpoint at a deflate block boundary every +span+ uncompressed
    # bytes (or more, since checkpoints only land on block boundaries).
    def self.build(path, span: DEFAULT_SPAN)
      index = new
      index.send(:build_from, path, span)
      index
    end

    # Load an index previously written with #save.  The index stays bound
    # to the identity of the gzip file it was built from.
    def self.load(index_path)
      payload =
        begin
          Marshal.load(File.binread(index_path))
        rescue TypeError, ArgumentError
          raise CorruptIndexError, "#{index_path} is not a gzip index file"
        end
      unless payload.is_a?(Hash) && payload['version'] == FORMAT_VERSION
        raise CorruptIndexError, "#{index_path} is not a gzip index file"
      end
      index = new
      index.send(:load_payload, payload)
      index
    end

    # Serialize this index to +index_path+.
    def save(index_path)
      raise Error, 'index has not been built yet' if @points.nil?

      payload = {
        'version' => FORMAT_VERSION,
        'span' => @span,
        'content_size' => @content_size,
        'content_crc32' => @content_crc32,
        'members' => @members,
        'verified' => @fully_verified,
        'source' => @source,
        'points' => @points.map { |p| [p.output, p.input, p.bits, p.window] }
      }
      File.binwrite(index_path, Marshal.dump(payload))
      index_path
    end

    # Identity of a gzip file: size, mtime and a CRC32 fingerprint of the
    # head and tail of the compressed file.
    def self.fingerprint(path)
      stat = File.stat(path)
      crc = Zlib.crc32
      File.open(path, 'rb') do |io|
        crc = Zlib.crc32(io.read(FINGERPRINT_BYTES) || ''.b, crc)
        if stat.size > FINGERPRINT_BYTES
          io.seek(-FINGERPRINT_BYTES, IO::SEEK_END)
          crc = Zlib.crc32(io.read(FINGERPRINT_BYTES) || ''.b, crc)
        end
      end
      {
        'size' => stat.size,
        'mtime' => stat.mtime.to_i,
        'mtime_nsec' => stat.mtime.nsec,
        'crc32' => crc
      }
    end

    # True when the file at +path+ still matches the identity recorded when
    # this index was built.
    def valid_for?(path)
      return false if @source.nil? || !File.file?(path)
      self.class.fingerprint(path) == @source
    rescue SystemCallError
      false
    end

    # Whole-stream CRC verification report.  +verified+ is true only when
    # every gzip member was inflated to its trailer and the stored CRC32
    # and ISIZE matched.  This is established while the index is built and
    # can be re-established on demand with #verify!.
    def verification
      {
        scope: :full_stream,
        verified: fully_verified?,
        crc32: @content_crc32,
        size: @content_size,
        members: @members
      }
    end

    # True when the whole gzip stream passed its trailer CRC32 and ISIZE
    # checks (during build or a later #verify!).
    def fully_verified?
      !!@fully_verified
    end

    # Re-inflate the entire gzip file at +path+, re-checking the CRC32 and
    # ISIZE of every member trailer.  Returns the whole-stream verification
    # report.
    def verify!(path)
      raise StaleIndexError, stale_message(path) unless valid_for?(path)
      scan(path, collect: false)
      verification
    end

    # Open the gzip file at +path+ for indexed random access.  Raises
    # StaleIndexError if the file changed since the index was built.
    # Returns a GzipIndex::Reader; with a block the reader is closed for
    # you.
    def open(path)
      raise StaleIndexError, stale_message(path) unless valid_for?(path)
      reader = Reader.new(self, path)
      return reader unless block_given?
      begin
        yield reader
      ensure
        reader.close
      end
    end

    # One-shot random access read: +length+ bytes of uncompressed data
    # starting at uncompressed +offset+.
    def read_at(path, offset, length)
      open(path) { |reader| reader.read_at(offset, length) }
    end

    # The checkpoint to resume from for uncompressed +offset+: the last
    # checkpoint whose uncompressed offset is not beyond +offset+.
    def point_for(offset)
      raise Error, 'index has not been built yet' if @points.nil?
      lo = 0
      hi = @points.length - 1
      while lo < hi
        mid = (lo + hi + 1) / 2
        if @points[mid].output <= offset
          lo = mid
        else
          hi = mid - 1
        end
      end
      @points[lo]
    end

    private

    def stale_message(path)
      "#{path} has changed since this index was built; rebuild the index"
    end

    def build_from(path, span)
      unless span.is_a?(Integer) && span >= 1
        raise ArgumentError, "span must be a positive integer, got #{span.inspect}"
      end
      @span = span
      @source = self.class.fingerprint(path)
      @points = [Point.new(0, 0, 0, ''.b)]
      scan(path, collect: true)
      self
    end

    def load_payload(payload)
      @span = payload['span']
      @content_size = payload['content_size']
      @content_crc32 = payload['content_crc32']
      @members = payload['members']
      @source = payload['source']
      @fully_verified = payload['verified'] ? true : false
      points = payload['points']
      unless points.is_a?(Array) && points.all? { |p| p.is_a?(Array) && p.length == 4 }
        raise CorruptIndexError, 'gzip index file is corrupt'
      end
      @points = points.map { |out, inp, bits, win| Point.new(out, inp, bits, win) }
      self
    end

    # Inflate the whole gzip file at +path+, letting inflate verify the
    # CRC32 and ISIZE of every member trailer.  When +collect+ is true,
    # checkpoints are appended to @points.
    def scan(path, collect:)
      strm = Z_stream.new
      err = inflateInit2(strm, GZIP_WBITS)
      raise_inflate_error(err, strm.msg) unless err == Z_OK

      history = +''.b
      outbuf = 0.chr * CHUNK_SIZE
      crc = Zlib.crc32
      totin = 0
      totout = 0
      last_point_out = 0
      members = 0
      need_reset = false

      File.open(path, 'rb') do |io|
        loop do
          chunk = io.read(CHUNK_SIZE)
          if chunk.nil? || chunk.empty?
            raise Error, 'unexpected end of gzip stream' unless need_reset
            break
          end
          if need_reset
            err = inflateReset(strm)
            raise_inflate_error(err, strm.msg) unless err == Z_OK
            need_reset = false
          end
          strm.next_in = Bytef.new(chunk)
          strm.avail_in = chunk.bytesize

          while strm.avail_in > 0
            strm.next_out = Bytef.new(outbuf)
            strm.avail_out = CHUNK_SIZE
            in_before = strm.avail_in
            ret = inflate(strm, Z_BLOCK)
            consumed = in_before - strm.avail_in
            produced = CHUNK_SIZE - strm.avail_out
            totin += consumed
            totout += produced

            if produced > 0
              piece = outbuf[0, produced]
              crc = Zlib.crc32(piece, crc)
              history << piece
              if history.bytesize > WINDOW_SIZE
                history = history[-WINDOW_SIZE, WINDOW_SIZE]
              end
            end

            if ret == Z_STREAM_END
              members += 1
              if strm.avail_in > 0
                err = inflateReset(strm)
                raise_inflate_error(err, strm.msg) unless err == Z_OK
              else
                need_reset = true
              end
            elsif ret != Z_OK && ret != Z_BUF_ERROR
              raise_inflate_error(ret, strm.msg)
            end

            # data_type bit 7: at a block boundary; bit 6: at the last
            # block.  Record a checkpoint only at block boundaries that
            # are not the end of the stream.
            if collect && (strm.data_type & 128) != 0 &&
               (strm.data_type & 64).zero? && totout - last_point_out >= @span
              @points << Point.new(totout, totin, strm.data_type & 7, history.dup)
              last_point_out = totout
            end
          end
        end
      end

      @content_size = totout
      @content_crc32 = crc
      @members = members
      @fully_verified = true
      self
    end

    def raise_inflate_error(ret, msg)
      case ret
      when Z_DATA_ERROR
        raise Zlib::DataError, msg
      when Z_MEM_ERROR
        raise Zlib::MemError, msg
      when Z_STREAM_ERROR
        raise Zlib::StreamError, msg
      when Z_BUF_ERROR
        raise Zlib::BufError, msg
      else
        raise Error, msg || "zlib error #{ret}"
      end
    end

    # Random-access reader bound to an open gzip file and an index built
    # for it.  Created via GzipIndex#open.
    class Reader
      attr_reader :index, :path, :last_verification

      def initialize(index, path)
        @index = index
        @path = path
        @io = File.open(path, 'rb')
        @last_verification = nil
      end

      # Uncompressed size of the gzip stream contents.
      def size
        @index.content_size
      end

      # Read +length+ bytes of uncompressed data starting at uncompressed
      # +offset+.  Returns a binary string, shorter than requested at end
      # of stream, and empty when +offset+ is beyond the end.
      def read_at(offset, length)
        raise Error, 'reader is closed' if @io.closed?
        unless offset.is_a?(Integer) && offset >= 0
          raise ArgumentError, "offset must be a non-negative integer, got #{offset.inspect}"
        end
        unless length.is_a?(Integer) && length >= 0
          raise ArgumentError, "length must be a non-negative integer, got #{length.inspect}"
        end
        return ''.b if length.zero? || offset >= @index.content_size

        point = @index.point_for(offset)
        data = inflate_from(point, offset, length)
        record_verification(offset, data)
        data
      end

      alias [] read_at

      def close
        @io.close unless @io.closed?
        nil
      end

      def closed?
        @io.closed?
      end

      private

      # Per-read CRC verification report.  A read that does not cover the
      # whole stream is reported with scope :partial and says nothing about
      # the integrity of the rest of the file.
      def record_verification(offset, data)
        crc = Zlib.crc32(data)
        full = offset.zero? && data.bytesize == @index.content_size
        @last_verification = {
          scope: full ? :full_stream : :partial,
          range: offset...(offset + data.bytesize),
          crc32: crc
        }
        if full
          @last_verification[:crc_matches] = (crc == @index.content_crc32)
        end
      end

      # Inflate starting at +point+, discard output up to +offset+, then
      # return up to +length+ bytes.
      def inflate_from(point, offset, length)
        strm = Z_stream.new
        raw = prepare_stream(strm, point)

        skip = offset - point.output
        result = +''.b
        discard = 0.chr * CHUNK_SIZE
        outbuf = 0.chr * CHUNK_SIZE
        need_reset = false

        while result.bytesize < length
          if strm.avail_in.nil? || strm.avail_in.zero?
            chunk = @io.read(CHUNK_SIZE)
            break if chunk.nil? || chunk.empty?
            if need_reset
              err = inflateInit2(strm, GZIP_WBITS)
              raise_inflate_error(err, strm.msg) unless err == Z_OK
              raw = false
              need_reset = false
            end
            strm.next_in = Bytef.new(chunk)
            strm.avail_in = chunk.bytesize
          end

          if skip.positive?
            want = [skip, CHUNK_SIZE].min
            strm.next_out = Bytef.new(discard)
          else
            want = [length - result.bytesize, CHUNK_SIZE].min
            strm.next_out = Bytef.new(outbuf)
          end
          strm.avail_out = want

          in_before = strm.avail_in
          ret = inflate(strm, Z_NO_FLUSH)
          consumed = in_before - strm.avail_in
          produced = want - strm.avail_out

          if skip.positive?
            skip -= produced
          else
            result << outbuf[0, produced]
          end

          case ret
          when Z_STREAM_END
            if raw
              # A raw inflate stops at the end of the deflate stream and
              # leaves the 8-byte gzip trailer (CRC32 + ISIZE) unread.
              # Skip it before looking for a concatenated member.
              break unless consume_input(strm, 8)
              raw = false
            end
            # Concatenated gzip member: re-initialize so the next member's
            # header is parsed and its trailer is checked.
            if strm.avail_in.positive?
              err = inflateInit2(strm, GZIP_WBITS)
              raise_inflate_error(err, strm.msg) unless err == Z_OK
            else
              need_reset = true
            end
          when Z_OK, Z_BUF_ERROR
            if consumed.zero? && produced.zero? && strm.avail_in.positive?
              raise Error, 'inflate is not making progress'
            end
          else
            raise_inflate_error(ret, strm.msg)
          end
        end

        result
      end

      # Discard +count+ compressed bytes from the stream input, reading
      # more from the underlying IO as needed.  Returns false when the
      # file ends first.
      def consume_input(strm, count)
        while count.positive?
          if strm.avail_in.positive?
            take = [strm.avail_in, count].min
            strm.next_in += take
            strm.avail_in -= take
            count -= take
          else
            chunk = @io.read([count, CHUNK_SIZE].min)
            return false if chunk.nil? || chunk.empty?
            strm.next_in = Bytef.new(chunk)
            strm.avail_in = chunk.bytesize
          end
        end
        true
      end

      # Position the stream and the underlying IO at +point+.
      # Returns true when the stream was initialized for raw deflate.
      def prepare_stream(strm, point)
        if point.output.zero?
          # No checkpoint covers the very start of the stream, so inflate
          # from the beginning, parsing the gzip header.
          err = inflateInit2(strm, GZIP_WBITS)
          raise_inflate_error(err, strm.msg) unless err == Z_OK
          @io.seek(0)
          return false
        end

        err = inflateInit2(strm, RAW_WBITS)
        raise_inflate_error(err, strm.msg) unless err == Z_OK

        if point.bits.zero?
          @io.seek(point.input)
        else
          # The checkpoint sits mid-byte: re-read that byte and feed the
          # bits that belong to the block starting at the boundary.
          @io.seek(point.input - 1)
          byte = @io.read(1)
          raise Error, 'unexpected end of gzip file' if byte.nil?
          err = inflatePrime(strm, point.bits, byte.getbyte(0) >> (8 - point.bits))
          raise_inflate_error(err, strm.msg) unless err == Z_OK
        end

        unless point.window.empty?
          strm.next_out = Bytef.new(+''.b)
          strm.avail_out = 0
          err = inflateSetDictionary(strm, point.window, point.window.bytesize)
          raise_inflate_error(err, strm.msg) unless err == Z_OK
        end
        true
      end

      def raise_inflate_error(ret, msg)
        case ret
        when Z_DATA_ERROR
          raise Zlib::DataError, msg
        when Z_MEM_ERROR
          raise Zlib::MemError, msg
        when Z_STREAM_ERROR
          raise Zlib::StreamError, msg
        when Z_BUF_ERROR
          raise Zlib::BufError, msg
        else
          raise Error, msg || "zlib error #{ret}"
        end
      end
    end
  end
end

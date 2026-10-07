# frozen_string_literal: true

require_relative 'gzip_index'

module Zlib
  class GzipIndex

    # Report describing a single random-access read. A read can only verify
    # the CRC32/ISIZE of members it covered from the very first byte to the
    # trailer; reads never establish integrity of the whole gzip file, so
    # full_file? is always false.
    class ReadReport
      attr_reader :range, :bytes_returned, :members_touched, :members_verified

      def initialize(range, bytes_returned, members_touched)
        @range = range
        @bytes_returned = bytes_returned
        @members_touched = members_touched
        @members_verified = []
      end

      # Always false: a partial read says nothing about the rest of the file.
      def full_file?
        false
      end

      # True only when every member this read touched was decompressed from
      # its first byte to its trailer and passed CRC32/ISIZE verification.
      def crc_verified?
        !@members_touched.empty? && (@members_touched - @members_verified).empty?
      end

      def to_s
        "partial read of #{@bytes_returned} bytes at "           "#{@range.begin}..#{@range.end - 1}: CRC32/ISIZE verified for "           "#{@members_verified.size} of #{@members_touched.size} member(s) "           'touched; full-file integrity NOT established'
      end
    end

    # Report describing a full-file verification pass (Reader#verify). Only
    # this report may claim whole-file integrity.
    class IntegrityReport
      attr_reader :members_verified, :errors
      attr_accessor :uncompressed_size

      def initialize
        @members_verified = []
        @uncompressed_size = 0
        @errors = []
      end

      # Always true: this report covers the entire gzip file.
      def full_file?
        true
      end

      # True when every member's CRC32 and ISIZE matched.
      def ok?
        @errors.empty?
      end

      def crc_ok?
        ok?
      end

      def to_s
        if ok?
          "full verification passed: #{@members_verified.size} member(s), "             "#{@uncompressed_size} uncompressed bytes, CRC32 and ISIZE verified"
        else
          "full verification FAILED: #{@errors.join('; ')}"
        end
      end
    end

    # Random-access reader over a gzip file, driven by a GzipIndex. Reads
    # start at the nearest checkpoint before the requested offset, restore
    # the inflate bit state and 32KB history window, and inflate forward
    # from there.
    class Reader
      attr_reader :path, :index, :last_report

      def initialize(path, index)
        @path = path
        @index = index
        @io = File.open(path, 'rb')
        @last_report = nil
      end

      # Uncompressed size of the whole gzip file.
      def size
        @index.uncompressed_size
      end

      def close
        @io.close unless @io.closed?
      end

      def closed?
        @io.closed?
      end

      # Read +length+ uncompressed bytes starting at +offset+. When +length+
      # is nil, reads to the end of the uncompressed data. A length running
      # past the end is clamped, so fewer bytes may be returned at EOF.
      #
      # After the call, #last_report holds a ReadReport describing exactly
      # which members were CRC-verified during this read.
      def read(offset, length = nil)
        raise GzipFile::Error, 'closed gzip index reader' if @io.closed?

        length = size - offset if length.nil?
        raise ArgumentError, "negative offset #{offset}" if offset.negative?
        raise ArgumentError, "negative length #{length}" if length.negative?
        return ''.b if length.zero? || offset >= size

        length = size - offset if offset + length > size

        member_first = @index.member_index_for(offset)
        member_last = @index.member_index_for(offset + length - 1)
        report = ReadReport.new(offset...(offset + length), length,
                                (member_first..member_last).to_a)
        checkpoint = @index.checkpoint_for(offset)
        covering = checkpoint.out_offset == @index.members[member_first].out_offset

        reader = ChunkReader.new(@io)
        strm = GzipIndex.new_raw_stream
        position_at_checkpoint(strm, reader, checkpoint)

        skip = offset - checkpoint.out_offset
        result = ''.b
        crc = 0
        member_out = 0
        member_idx = member_first

        loop do
          if strm.avail_in.nil? || strm.avail_in.zero?
            chunk = reader.read(INPUT_CHUNK)
            if chunk.empty?
              raise TruncatedError, 'unexpected end of file inside deflate stream'
            end

            strm.next_in = Rbzlib::Bytef.new(chunk)
            strm.avail_in = chunk.bytesize
          end

          out_buf = 0.chr * OUTPUT_CHUNK
          strm.next_out = Rbzlib::Bytef.new(out_buf)
          strm.avail_out = OUTPUT_CHUNK
          ret = Rbzlib.inflate(strm, Rbzlib::Z_NO_FLUSH)
          produced_len = OUTPUT_CHUNK - strm.avail_out

          if produced_len.positive?
            produced = out_buf.byteslice(0, produced_len)
            crc = Rbzlib.crc32(crc, produced) if covering
            member_out += produced_len
            if skip >= produced_len
              skip -= produced_len
            else
              take = produced.byteslice(skip, produced_len - skip)
              skip = 0
              result << take.byteslice(0, length - result.bytesize)
            end
          end

          if ret == Rbzlib::Z_STREAM_END
            leftover = strm.avail_in && strm.avail_in.positive? ? strm.next_in.current : ''.b
            reader.unread(leftover)
            Rbzlib.inflateEnd(strm)
            if covering
              GzipIndex.verify_member_trailer(reader, crc, member_out, member_idx)
              report.members_verified << member_idx
            else
              reader.read(8) # skip trailer; cannot verify a partially covered member
            end
            break if result.bytesize >= length

            member_idx += 1
            if member_idx >= @index.members.size
              raise TruncatedError, 'gzip data ended before the requested range'
            end
            GzipIndex.parse_member_header(reader)
            strm = GzipIndex.new_raw_stream
            covering = true
            crc = 0
            member_out = 0
          elsif ret == Rbzlib::Z_OK || ret == Rbzlib::Z_BUF_ERROR
            if ret == Rbzlib::Z_BUF_ERROR && !strm.avail_in.zero?
              Rbzlib.inflateEnd(strm)
              raise GzipFile::Error, 'inflate made no progress'
            end
            break if result.bytesize >= length
          else
            msg = strm.msg
            Rbzlib.inflateEnd(strm)
            raise GzipFile::Error, "inflate failed: #{Rbzlib.zError(ret)} (#{msg})"
          end
        end

        Rbzlib.inflateEnd(strm) if result.bytesize >= length && !strm.state.nil?
        @last_report = report
        result
      end

      # Verify the integrity of the entire gzip file: inflate every member
      # from start to finish and check each member's CRC32 and ISIZE.
      # Returns an IntegrityReport; use #verify! to raise on failure instead.
      def verify
        raise GzipFile::Error, 'closed gzip index reader' if @io.closed?

        report = IntegrityReport.new
        reader = ChunkReader.new(@io)
        reader.seek(0)
        member_idx = 0

        loop do
          begin
            header = GzipIndex.parse_member_header(reader)
            break if header.nil?

            strm = GzipIndex.new_raw_stream
            crc = 0
            member_out = 0

            begin
              loop do
                if strm.avail_in.nil? || strm.avail_in.zero?
                  chunk = reader.read(INPUT_CHUNK)
                  if chunk.empty?
                    raise TruncatedError, 'unexpected end of file inside deflate stream'
                  end

                  strm.next_in = Rbzlib::Bytef.new(chunk)
                  strm.avail_in = chunk.bytesize
                end

                out_buf = 0.chr * OUTPUT_CHUNK
                strm.next_out = Rbzlib::Bytef.new(out_buf)
                strm.avail_out = OUTPUT_CHUNK
                ret = Rbzlib.inflate(strm, Rbzlib::Z_NO_FLUSH)
                produced = OUTPUT_CHUNK - strm.avail_out
                if produced.positive?
                  crc = Rbzlib.crc32(crc, out_buf.byteslice(0, produced))
                  member_out += produced
                end

                break if ret == Rbzlib::Z_STREAM_END

                unless ret == Rbzlib::Z_OK || ret == Rbzlib::Z_BUF_ERROR
                  raise GzipFile::Error, "inflate failed: #{Rbzlib.zError(ret)} (#{strm.msg})"
                end
                if ret == Rbzlib::Z_BUF_ERROR && !strm.avail_in.zero?
                  raise GzipFile::Error, 'inflate made no progress'
                end
              end
            ensure
              leftover = strm.avail_in && strm.avail_in.positive? ? strm.next_in.current : ''.b
              Rbzlib.inflateEnd(strm)
            end

            reader.unread(leftover)
            GzipIndex.verify_member_trailer(reader, crc, member_out, member_idx)
            report.members_verified << member_idx
            report.uncompressed_size += member_out
            member_idx += 1
          rescue Zlib::Error => e
            report.errors << "member #{member_idx}: #{e.message}"
            break
          end
        end

        @last_report = report
        report
      end

      # Like #verify, but raises GzipFile::Error when verification fails.
      def verify!
        report = verify
        raise GzipFile::Error, report.errors.join('; ') unless report.ok?

        report
      end

      private

      # Seek +reader+ to the checkpoint and restore the inflate bit state
      # (priming leftover bits of a partially consumed byte) and the 32KB
      # history window saved in the checkpoint.
      def position_at_checkpoint(strm, reader, checkpoint)
        if checkpoint.bits.zero?
          reader.seek(checkpoint.in_offset)
        else
          reader.seek(checkpoint.in_offset - 1)
          byte = reader.read(1).getbyte(0)
          err = Rbzlib.inflatePrime(strm, checkpoint.bits, byte >> (8 - checkpoint.bits))
          unless err == Rbzlib::Z_OK
            raise GzipFile::Error, "inflatePrime failed: #{Rbzlib.zError(err)}"
          end
        end
        return if checkpoint.window.empty?

        strm.next_out = Rbzlib::Bytef.new(''.b)
        strm.avail_out = 0
        err = Rbzlib.inflateSetDictionary(strm, checkpoint.window, checkpoint.window.bytesize)
        unless err == Rbzlib::Z_OK
          raise GzipFile::Error, "inflateSetDictionary failed: #{Rbzlib.zError(err)}"
        end
      end
    end
  end
end

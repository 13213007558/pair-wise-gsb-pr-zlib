# frozen_string_literal: true

module Zlib
  # Zlib::InflateIndex
  #
  # An optional diagnostic index that can be attached to Zlib::Inflate via
  # Zlib::Inflate#enable_diagnostics. While attached, every deflate token
  # (literal or length/distance back-reference) that inflate emits is recorded
  # together with:
  #
  # * the compressed bit range the token was decoded from (absolute bit
  #   offsets into the compressed input stream, including any zlib/gzip
  #   wrapper bytes),
  # * the output byte range the token produced,
  # * for back-references, the source output range the bytes were copied from.
  #
  # Given an output position, #trace walks the chain of back-references back
  # to the literal the byte ultimately originated from. Self-overlapping
  # matches (distance < length) are followed one hop at a time with strictly
  # decreasing positions plus a visited guard, so they terminate instead of
  # expanding into an infinite source chain.
  #
  # Pass output_range to restrict detailed recording to tokens whose output
  # intersects that range; tokens outside it are not recorded and traces that
  # reach them stop with an unresolved hop. When no index is attached, inflate
  # keeps no per-byte records at all.
  class InflateIndex
    # A single recorded deflate token.
    class Token
      attr_reader :kind, :bit_start, :bit_end, :out_start, :out_end, :distance, :byte

      def initialize(kind, bit_start, bit_end, out_start, out_end, distance = nil, byte = nil)
        @kind = kind
        @bit_start = bit_start
        @bit_end = bit_end
        @out_start = out_start
        @out_end = out_end
        @distance = distance
        @byte = byte
      end

      def literal?
        @kind == :literal
      end

      def match?
        @kind == :match
      end

      def length
        @out_end - @out_start
      end

      def bit_length
        @bit_end - @bit_start
      end

      def bit_range
        @bit_start...@bit_end
      end

      def out_range
        @out_start...@out_end
      end

      def src_start
        match? ? @out_start - @distance : nil
      end

      def src_end
        match? ? @out_end - @distance : nil
      end

      def src_range
        match? ? (src_start...src_end) : nil
      end

      def cover?(out_pos)
        @out_start <= out_pos && out_pos < @out_end
      end

      def to_s
        if literal?
          format('#<Zlib::InflateIndex::Token literal byte=0x%02x out=%d bits=%d...%d>',
            @byte, @out_start, @bit_start, @bit_end)
        else
          format('#<Zlib::InflateIndex::Token match len=%d dist=%d out=%d...%d src=%d...%d bits=%d...%d>',
            length, @distance, @out_start, @out_end, src_start, src_end, @bit_start, @bit_end)
        end
      end
      alias inspect to_s
    end

    # One step of a #trace path: the token covering +out_pos+, and +src_pos+,
    # the earlier output position the byte was copied from (nil for literals).
    # A hop with a nil token is unresolved: no token covering that position
    # was recorded (e.g. outside a restricted output_range).
    class Hop
      attr_reader :token, :out_pos, :src_pos

      def initialize(token, out_pos, src_pos)
        @token = token
        @out_pos = out_pos
        @src_pos = src_pos
      end

      def resolved?
        !@token.nil?
      end

      def literal?
        resolved? && @token.literal?
      end

      def to_s
        if !resolved?
          "#<Zlib::InflateIndex::Hop unresolved out=#{out_pos}>"
        elsif literal?
          format('#<Zlib::InflateIndex::Hop literal out=%d byte=0x%02x>', @out_pos, @token.byte)
        else
          format('#<Zlib::InflateIndex::Hop match out=%d <- src=%d (dist=%d)>',
            @out_pos, @src_pos, @token.distance)
        end
      end
      alias inspect to_s
    end

    attr_reader :tokens, :output_range
    attr_accessor :pending_bit_start

    def initialize(output_range: nil)
      @tokens = []
      @output_range = output_range
      if output_range
        @range_begin = output_range.begin || 0
        @range_end = output_range.exclude_end? ? output_range.end : output_range.end + 1
      end
    end

    def begin_token(bit_start)
      @pending_bit_start = bit_start
    end

    def record_literal(bit_start, bit_end, out_pos, byte)
      return unless record?(out_pos, out_pos + 1)

      @tokens << Token.new(:literal, bit_start, bit_end, out_pos, out_pos + 1, nil, byte)
    end

    def record_match(bit_start, bit_end, out_start, length, distance)
      return unless record?(out_start, out_start + length)

      last = @tokens.last
      if last && last.match? && last.bit_start == bit_start &&
          last.distance == distance && last.out_end == out_start
        @tokens[-1] = Token.new(:match, last.bit_start, bit_end,
          last.out_start, out_start + length, distance)
      else
        @tokens << Token.new(:match, bit_start, bit_end, out_start, out_start + length, distance)
      end
    end

    def token_at(out_pos)
      index = @tokens.bsearch_index { |token| token.out_end > out_pos }
      return nil unless index

      token = @tokens[index]
      token.cover?(out_pos) ? token : nil
    end

    def trace(out_pos)
      path = []
      pos = out_pos
      seen = {}
      loop do
        token = token_at(pos)
        if token.nil?
          path << Hop.new(nil, pos, nil)
          break
        end
        if token.literal?
          path << Hop.new(token, pos, nil)
          break
        end
        src = pos - token.distance
        path << Hop.new(token, pos, src)
        key = [token.object_id, pos]
        break if seen[key]

        seen[key] = true
        pos = src
      end
      path
    end

    def origin(out_pos)
      trace(out_pos).last
    end

    private

    def record?(out_start, out_end)
      return true if @range_begin.nil?

      out_end > @range_begin && out_start < @range_end
    end
  end
end

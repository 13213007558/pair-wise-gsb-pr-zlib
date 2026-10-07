# frozen_string_literal: true

module Zlib
  # InflateIndex is an optional diagnostic index for Zlib::Inflate. When
  # attached (see Zlib::Inflate#enable_diag_index) the inflate core records
  # one Token per deflate token it emits: literals, length/distance pairs
  # (back references) and stored blocks.
  #
  # Each token maps the compressed bit range it was decoded from to the
  # output range it produced, and match tokens know the output position
  # they copy from. This makes it possible to answer 'which compressed
  # bits produced this output byte?' and to trace any output byte back
  # through a chain of back references to the literal it originated from.
  #
  # Pass an output range to limit detailed recording (compressed bit
  # ranges) to tokens intersecting that range. Tokens outside the range
  # are still recorded, but only compactly (kind, output range, distance),
  # which is enough to keep #trace working across the whole stream.
  #
  # When no index is attached the inflate core keeps no per-token records
  # at all.
  #
  # Example:
  #
  #   inflate = Zlib::Inflate.new(-15)
  #   index = inflate.enable_diag_index
  #   output = inflate.inflate(compressed)
  #   index.trace(output.length - 1).each do |step|
  #     p [step.out_pos, step.token.kind, step.token.out_range]
  #   end
  #
  class InflateIndex
    # One deflate token: a literal, a match (length/distance pair) or a
    # stored (uncompressed) block.
    #
    # * kind:      :literal, :match or :stored
    # * bit_begin: first compressed input bit of this token (nil unless
    #              the token is inside the detailed output range)
    # * bit_end:   one past the last compressed input bit (nil as above)
    # * out_begin: first output byte produced by this token
    # * out_end:   one past the last output byte produced by this token
    # * distance:  copy distance for :match tokens, nil otherwise
    # * detail:    true when recorded inside the detailed output range
    Token = Struct.new(:kind, :bit_begin, :bit_end, :out_begin, :out_end, :distance, :detail) do
      def length
        out_end - out_begin
      end

      def literal?
        kind == :literal
      end

      def match?
        kind == :match
      end

      def stored?
        kind == :stored
      end

      # First output position this token copies from (match tokens only).
      def source_begin
        match? ? out_begin - distance : nil
      end

      def covers?(out_pos)
        out_begin <= out_pos && out_pos < out_end
      end

      def bit_range
        bit_begin.nil? || bit_end.nil? ? nil : bit_begin...bit_end
      end

      def out_range
        out_begin...out_end
      end
    end

    # One hop of a #trace path: the output position being resolved and the
    # token that produced it. A nil token means the position could not be
    # resolved (e.g. it refers to a preset dictionary or to output produced
    # before the index was attached).
    Step = Struct.new(:out_pos, :token)

    attr_reader :tokens, :out_range

    # out_range: optional Range of output positions to record in detail
    # (with compressed bit ranges). Nil records every token in detail.
    def initialize(out_range = nil)
      @out_range = out_range
      @tokens = []
    end

    # Record one deflate token. Called by the inflate core; not part of
    # the public API.
    def record(kind, bit_begin, bit_end, out_begin, out_end, distance = nil)
      if detailed?(out_begin, out_end)
        @tokens << Token.new(kind, bit_begin, bit_end, out_begin, out_end, distance, true)
      else
        @tokens << Token.new(kind, nil, nil, out_begin, out_end, distance, false)
      end
      self
    end

    # The token that produced output byte +out_pos+, or nil.
    def token_at(out_pos)
      i = @tokens.bsearch_index { |token| token.out_end > out_pos }
      token = i && @tokens[i]
      token && token.covers?(out_pos) ? token : nil
    end

    # Trace the output byte at +out_pos+ back to its origin. Returns an
    # array of Step, starting with the queried position and ending with
    # the literal (or stored block) the byte originated from.
    #
    # A self-overlapping match (distance smaller than length) is collapsed
    # within its own token in a single hop, so the chain is always finite.
    def trace(out_pos)
      steps = []
      pos = out_pos
      loop do
        token = token_at(pos)
        steps << Step.new(pos, token)
        break if token.nil? || !token.match?

        pos = token.out_begin - token.distance + (pos - token.out_begin) % token.distance
      end
      steps
    end

    # The final step of #trace: where the byte at +out_pos+ originates.
    def origin(out_pos)
      trace(out_pos).last
    end

    private

    def detailed?(out_begin, out_end)
      return true if @out_range.nil?

      lo = @out_range.begin || 0
      hi = @out_range.end
      hi = Float::INFINITY if hi.nil?
      hi += 1 if hi.finite? && !@out_range.exclude_end?
      out_begin < hi && out_end > lo
    end
  end
end


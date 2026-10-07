# frozen_string_literal: true

########################################################################
# inflate_index_spec.rb
#
# Spec for Zlib::InflateIndex, the optional inflate diagnostic index.
#
# The compressed data is a hand-crafted raw deflate stream (fixed Huffman
# block) so every token boundary and bit offset can be verified by hand:
#
#   header      BFINAL=1, BTYPE=01 (fixed)              bits   0...3
#   literal 'a' 8-bit fixed code 0xC1                   bits   3...11
#   literal 'b' 8-bit fixed code 0xC2                   bits  11...19
#   literal 'c' 8-bit fixed code 0xC3                   bits  19...27
#   match       len=3 (code 257, 7 bits), dist=3 (code 2, 5 bits)
#                                                       bits  27...39  -> out 3...6
#   match       len=6 (code 260, 7 bits), dist=6 (code 4, 5 bits + 1 extra)
#                                                       bits  39...52  -> out 6...12
#   match       len=6 (code 260, 7 bits), dist=2 (code 1, 5 bits)
#                                                       bits  52...64  -> out 12...18 (self-overlapping)
#   end-of-block code 256 (7 bits)                      bits  64...71
#
# Expected output: "abc" + "abc" + "abcabc" + "bcbcbc" (18 bytes).
# Tracing the last byte (offset 17) walks:
#   17 -dist2-> 15 -dist2-> 13 -dist2-> 11 -dist6-> 5 -dist3-> 2 (literal 'c')
########################################################################
require 'spec_helper'

RSpec.describe Zlib::InflateIndex do
  # Packs bits LSB-first into bytes, as deflate requires. Huffman codes are
  # emitted MSB-first via put_code; everything else via put_bits.
  class BitPacker
    def initialize
      @acc = 0
      @nbits = 0
      @bytes = []
    end

    def put_bits(value, count)
      @acc |= (value & ((1 << count) - 1)) << @nbits
      @nbits += count
      while @nbits >= 8
        @bytes << (@acc & 0xff)
        @acc >>= 8
        @nbits -= 8
      end
    end

    def put_code(code, count)
      reversed = 0
      count.times { |i| reversed |= ((code >> i) & 1) << (count - 1 - i) }
      put_bits(reversed, count)
    end

    def finish
      @bytes << (@acc & 0xff) if @nbits > 0
      @bytes.pack('C*')
    end
  end

  def fixed_code(symbol)
    if symbol < 144
      [0x30 + symbol, 8]
    elsif symbol < 256
      [0x190 + symbol - 144, 9]
    elsif symbol < 280
      [symbol - 256, 7]
    else
      [0xc0 + symbol - 280, 8]
    end
  end

  let(:deflate_data) do
    packer = BitPacker.new
    emit = lambda do |symbol|
      code, width = fixed_code(symbol)
      packer.put_code(code, width)
    end
    packer.put_bits(1, 1) # BFINAL
    packer.put_bits(1, 2) # BTYPE = fixed Huffman
    emit.call(97)         # 'a'
    emit.call(98)         # 'b'
    emit.call(99)         # 'c'
    emit.call(257)        # length 3
    packer.put_code(2, 5) # distance 3
    emit.call(260)        # length 6
    packer.put_code(4, 5) # distance code 4: base 5, 1 extra bit
    packer.put_bits(1, 1) # extra: distance 6
    emit.call(260)        # length 6
    packer.put_code(1, 5) # distance 2 (self-overlapping)
    emit.call(256)        # end of block
    packer.finish
  end

  let(:expected_output) { 'abcabcabcabcbcbcbc' }

  let(:inflate) do
    inflater = Zlib::Inflate.new(-15)
    inflater.enable_diagnostics
    inflater
  end

  let(:index) { inflate.diagnostic_index }

  def inflate_all
    output = inflate.inflate(deflate_data)
    output << inflate.inflate(nil)
    output
  end

  it 'produces the expected output' do
    expect(inflate_all).to eq(expected_output)
  end

  it 'records one token per literal and per back-reference' do
    inflate_all
    expect(index.tokens.map(&:kind)).to eq(
      [:literal, :literal, :literal, :match, :match, :match]
    )
  end

  it 'records the compressed bit range of each token' do
    inflate_all
    ranges = index.tokens.map { |token| [token.bit_start, token.bit_end] }
    expect(ranges).to eq([[3, 11], [11, 19], [19, 27], [27, 39], [39, 52], [52, 64]])
  end

  it 'records the output range of each token' do
    inflate_all
    ranges = index.tokens.map { |token| [token.out_start, token.out_end] }
    expect(ranges).to eq([[0, 1], [1, 2], [2, 3], [3, 6], [6, 12], [12, 18]])
  end

  it 'records the back-reference source of each match' do
    inflate_all
    matches = index.tokens.select(&:match?)
    expect(matches.map(&:distance)).to eq([3, 6, 2])
    expect(matches.map(&:src_range)).to eq([0...3, 0...6, 10...16])
  end

  it 'records literal bytes' do
    inflate_all
    expect(index.tokens.select(&:literal?).map(&:byte)).to eq([97, 98, 99])
  end

  describe '#trace' do
    it 'traces the final byte back through every layer to the original literal' do
      output = inflate_all
      path = index.trace(17)

      expect(path.map(&:out_pos)).to eq([17, 15, 13, 11, 5, 2])
      expect(path.map(&:src_pos)).to eq([15, 13, 11, 5, 2, nil])
      expect(path.map { |hop| hop.token&.distance }).to eq([2, 2, 2, 6, 3, nil])

      final = path.last
      expect(final).to be_literal
      expect(final.token.byte).to eq(99) # 'c'
      expect(output[17]).to eq('c')
    end

    it 'terminates on self-overlapping matches instead of looping forever' do
      inflate_all
      path = index.trace(12)
      expect(path.map(&:out_pos)).to eq([12, 10, 4, 1])
      expect(path.last.token.byte).to eq(98) # 'b'
    end

    it 'traces a byte copied from the sliding window region' do
      inflate_all
      path = index.trace(16)
      expect(path.map(&:out_pos)).to eq([16, 14, 12, 10, 4, 1])
      expect(path.last.token.byte).to eq(98) # 'b'
    end

    it 'returns a single literal hop for bytes that were literals' do
      inflate_all
      path = index.trace(0)
      expect(path.size).to eq(1)
      expect(path.first.token.byte).to eq(97) # 'a'
    end

    it 'marks positions with no recorded token as unresolved' do
      inflate_all
      expect(index.trace(100).last).not_to be_resolved
    end
  end

  describe '#origin' do
    it 'returns the terminal literal hop directly' do
      inflate_all
      origin = index.origin(17)
      expect(origin).to be_literal
      expect(origin.token.byte).to eq(99)
    end
  end

  describe 'output_range restriction' do
    let(:inflate) do
      inflater = Zlib::Inflate.new(-15)
      inflater.enable_diagnostics(output_range: 12...18)
      inflater
    end

    it 'only records tokens intersecting the given output range' do
      inflate_all
      expect(index.tokens.size).to eq(1)
      token = index.tokens.first
      expect(token.out_range).to eq(12...18)
      expect(token.distance).to eq(2)
    end

    it 'stops the trace with an unresolved hop outside the recorded range' do
      inflate_all
      path = index.trace(17)
      expect(path.map(&:out_pos)).to eq([17, 15, 13, 11])
      expect(path.last).not_to be_resolved
    end
  end

  describe 'diagnostics disabled' do
    it 'keeps no records and does not change inflate behavior' do
      inflater = Zlib::Inflate.new(-15)
      expect(inflater.diagnostic_index).to be_nil
      output = inflater.inflate(deflate_data)
      output << inflater.inflate(nil)
      expect(output).to eq(expected_output)
      expect(inflater.diagnostic_index).to be_nil
    end

    it 'stops recording after disable_diagnostics' do
      inflater = Zlib::Inflate.new(-15)
      inflater.enable_diagnostics
      inflater.disable_diagnostics
      inflater.inflate(deflate_data)
      inflater.inflate(nil)
      expect(inflater.diagnostic_index).to be_nil
    end
  end

  describe 'slow path decoding' do
    it 'records identical tokens when input arrives one byte at a time' do
      inflater = Zlib::Inflate.new(-15)
      inflater.enable_diagnostics
      output = +''
      deflate_data.each_byte { |byte| output << inflater.inflate(byte.chr) }
      output << inflater.inflate(nil)

      expect(output).to eq(expected_output)
      index = inflater.diagnostic_index
      expect(index.tokens.map(&:kind)).to eq(
        [:literal, :literal, :literal, :match, :match, :match]
      )
      ranges = index.tokens.map { |token| [token.bit_start, token.bit_end] }
      expect(ranges).to eq([[3, 11], [11, 19], [19, 27], [27, 39], [39, 52], [52, 64]])
      expect(index.trace(17).map(&:out_pos)).to eq([17, 15, 13, 11, 5, 2])
    end
  end
end

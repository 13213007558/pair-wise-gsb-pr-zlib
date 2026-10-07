# frozen_string_literal: true

########################################################################
# inflate_index_spec.rb
#
# Spec for the Zlib::InflateIndex diagnostic index.
########################################################################
require 'spec_helper'

RSpec.describe Zlib::InflateIndex do
  # Assembles a raw deflate stream bit by bit (LSB-first per byte,
  # Huffman codes MSB-first, extra bits LSB-first).
  class BitWriter
    def initialize
      @bits = []
    end

    def push_code(code, len)
      (len - 1).downto(0) { |i| @bits << ((code >> i) & 1) }
    end

    def push_extra(value, len)
      len.times { |i| @bits << ((value >> i) & 1) }
    end

    def to_s
      @bits.each_slice(8).map do |slice|
        byte = 0
        slice.each_with_index { |b, i| byte |= b << i }
        byte
      end.pack('C*')
    end
  end

  # Hand-crafted fixed-Huffman deflate stream with three levels of back
  # references, including a self-overlapping match:
  #
  #   literal 'a'          -> out[0]
  #   literal 'b'          -> out[1]
  #   match len=5 dist=2   -> out[2..6]  'ababa' (self-overlapping)
  #   literal 'c'          -> out[7]
  #   match len=4 dist=8   -> out[8..11] copies out[0..3]
  #   match len=4 dist=4   -> out[12..15] copies out[8..11]
  #
  # Output: 'abababacabababab'
  let(:stream) do
    w = BitWriter.new
    w.push_extra(1, 1)   # BFINAL
    w.push_extra(1, 2)   # BTYPE = fixed Huffman
    w.push_code(0x91, 8) # literal 'a' (fixed code 0x30 + 0x61)
    w.push_code(0x92, 8) # literal 'b'
    w.push_code(3, 7)    # length symbol 259 (len 5)
    w.push_code(1, 5)    # distance symbol 1 (dist 2)
    w.push_code(0x93, 8) # literal 'c'
    w.push_code(2, 7)    # length symbol 258 (len 4)
    w.push_code(5, 5)    # distance symbol 5 (base 7, 1 extra bit)
    w.push_extra(1, 1)   # extra -> dist 8
    w.push_code(2, 7)    # length symbol 258 (len 4)
    w.push_code(3, 5)    # distance symbol 3 (dist 4)
    w.push_code(0, 7)    # end of block (256)
    w.to_s
  end

  let(:inflate) do
    inf = Zlib::Inflate.new(-15)
    inf.enable_diag_index
    inf
  end

  let(:output) { inflate.inflate(stream) }
  let(:index) { inflate.diag_index }

  it 'decodes the hand-crafted stream correctly' do
    expect(output).to eq('abababacabababab')
  end

  it 'records one token per deflate token with output ranges' do
    output
    expect(index.tokens.map { |t| [t.kind, t.out_begin, t.out_end, t.distance] }).to eq(
      [[:literal, 0, 1, nil],
       [:literal, 1, 2, nil],
       [:match, 2, 7, 2],
       [:literal, 7, 8, nil],
       [:match, 8, 12, 8],
       [:match, 12, 16, 4]]
    )
  end

  it 'records the compressed bit range of each token' do
    output
    expect(index.tokens.map { |t| [t.bit_begin, t.bit_end] }).to eq(
      [[3, 11], [11, 19], [19, 31], [31, 39], [39, 52], [52, 64]]
    )
  end

  it 'traces a trailing byte back through multi-level back references' do
    output
    path = index.trace(15)
    expect(path.map(&:out_pos)).to eq([15, 11, 3, 1])
    expect(path.map { |s| s.token.kind }).to eq([:match, :match, :match, :literal])
    expect(output[path.last.out_pos]).to eq('b')
    expect(output[15]).to eq('b')
  end

  it 'collapses self-overlapping matches into a finite chain' do
    output
    path = index.trace(6)
    expect(path.map(&:out_pos)).to eq([6, 0])
    expect(path.last.token.kind).to eq(:literal)
    expect(output[6]).to eq('a')
  end

  it 'resolves the origin of every output byte' do
    output
    output.bytes.each_with_index do |byte, pos|
      origin = index.origin(pos)
      expect(origin.token).not_to be_nil
      expect(origin.token.kind).not_to eq(:match)
      expect(output.getbyte(origin.out_pos)).to eq(byte)
    end
  end

  context 'with a detailed output range' do
    let(:inflate) do
      inf = Zlib::Inflate.new(-15)
      inf.enable_diag_index(12...16)
      inf
    end

    it 'only records bit ranges inside the range' do
      output
      detailed = index.tokens.select(&:detail)
      expect(detailed.size).to eq(1)
      expect(detailed.first.out_range).to eq(12...16)
      expect(detailed.first.bit_range).to eq(52...64)
      expect(index.tokens.first.bit_range).to be_nil
    end

    it 'still traces through compact tokens outside the range' do
      output
      expect(index.trace(15).map(&:out_pos)).to eq([15, 11, 3, 1])
    end
  end

  context 'when diagnostics are disabled' do
    it 'keeps no token records' do
      inf = Zlib::Inflate.new(-15)
      expect(inf.diag_index).to be_nil
      expect(inf.inflate(stream)).to eq('abababacabababab')
      expect(inf.diag_index).to be_nil
    end

    it 'stops recording after disable_diag_index' do
      inf = Zlib::Inflate.new(-15)
      index = inf.enable_diag_index
      inf.disable_diag_index
      expect(inf.inflate(stream)).to eq('abababacabababab')
      expect(index.tokens).to be_empty
      expect(inf.diag_index).to be_nil
    end
  end

  context 'with a zlib-wrapped dynamic stream' do
    let(:source) { 'the quick brown fox jumps over the lazy dog. ' * 20 }
    let(:compressed) { Zlib::Deflate.deflate(source) }
    let(:inflate) do
      inf = Zlib::Inflate.new
      inf.enable_diag_index
      inf
    end

    it 'covers every output byte with contiguous bit ranges' do
      out = inflate.inflate(compressed)
      expect(out).to eq(source)
      pos = 0
      index.tokens.each do |token|
        expect(token.out_begin).to be <= pos
        pos = token.out_end if token.out_end > pos
      end
      expect(pos).to eq(out.length)
      bit = index.tokens.first.bit_begin
      index.tokens.each do |token|
        expect(token.bit_begin).to eq(bit)
        bit = token.bit_end
      end
    end

    it 'traces a late output byte to a literal' do
      out = inflate.inflate(compressed)
      origin = index.origin(out.length - 1)
      expect(origin.token.kind).to eq(:literal)
      expect(out.getbyte(origin.out_pos)).to eq(out.getbyte(out.length - 1))
    end
  end
end

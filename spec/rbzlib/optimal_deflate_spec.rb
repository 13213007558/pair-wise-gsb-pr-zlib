# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'optimal deflate' do
  def optimal(input, **options)
    Zlib::Deflate.optimal_deflate(input, **options)
  end

  def random_bytes(length, seed)
    random = Random.new(seed)
    Array.new(length) { random.rand(256) }.pack('C*')
  end

  it 'returns output and search diagnostics' do
    result = optimal('hello hello hello')

    expect(result).to be_a(Rbzlib::OptimalResult)
    expect(Zlib::Inflate.inflate(result.output)).to eq('hello hello hello')
    expect(result.diagnostics).to include(
      search: :exhaustive,
      complete: true,
      exhaustive: true,
      lz77_window_reset: false
    )
    expect(result.diagnostics[:evaluations]).to be > 0
    expect(result.diagnostics[:blocks]).not_to be_empty
  end

  it 'accounts for headers, extra bits, and final block alignment' do
    result = optimal('abc')
    wrapper = 2 * 8 + 4 * 8
    raw_bit_count = (result.output.bytesize * 8) - wrapper

    expect(result.diagnostics[:bit_cost]).to eq(raw_bit_count)
    expect(raw_bit_count % 8).to eq(0)
  end

  it 'searches every block boundary for short inputs' do
    input = 'abracadabra' * 3
    result = optimal(input)

    expect(result.diagnostics[:exhaustive]).to be(true)
    expect(result.diagnostics[:complete]).to be(true)
    expect(result.diagnostics[:budget]).to eq(Rbzlib::OptimalPlanner::DEFAULT_BUDGET)
    expect(result.diagnostics[:evaluations]).to eq(
      result.diagnostics[:tokens] * (result.diagnostics[:tokens] + 1) / 2
    )
  end

  it 'can choose fixed and dynamic Huffman blocks' do
    fixed = optimal('hello hello hello')
    dynamic = optimal('ab' * 10_000, budget: 100)

    expect(fixed.diagnostics[:block_counts]).to include(fixed: 1)
    expect(dynamic.diagnostics[:block_counts]).to include(dynamic: 1)
    expect(Zlib::Inflate.inflate(fixed.output)).to eq('hello hello hello')
    expect(Zlib::Inflate.inflate(dynamic.output)).to eq('ab' * 10_000)
  end

  it 'uses stored blocks for incompressible data' do
    input = random_bytes(500, 7)
    result = optimal(input)

    expect(result.diagnostics[:block_counts]).to include(stored: 1)
    expect(Zlib::Inflate.inflate(result.output)).to eq(input)
  end

  it 'keeps the LZ77 window across planned block boundaries' do
    random = Random.new(42)
    input = Array.new(70_000) { random.rand(256) }.pack('C*')
    input << input[1000, 3000]
    result = optimal(input, budget: 100)

    expect(result.diagnostics[:blocks].length).to be > 1
    expect(result.diagnostics[:lz77_window_reset]).to be(false)
    expect(Zlib::Inflate.inflate(result.output)).to eq(input)
  end

  it 'does not reset LZ77 history at a nearby block boundary' do
    phrase = 'cross-block-reference'
    input = random_bytes(65_518, 42) + phrase + phrase
    result = optimal(input, budget: 10)

    expect(result.diagnostics[:blocks].length).to be > 1
    expect(result.diagnostics[:tokens]).to be < input.length
    expect(Zlib::Inflate.inflate(result.output)).to eq(input)
  end

  it 'reports when a bounded search does not spend its full budget' do
    input = Array.new(200_000) { |index| (index * 73 + (index * index / 13)) % 256 }.pack('C*')
    result = optimal(input, budget: 1)

    expect(result.diagnostics[:search]).to eq(:bounded)
    expect(result.diagnostics[:exhaustive]).to be(false)
    expect(result.diagnostics[:complete]).to be(false)
    expect(result.diagnostics[:evaluations]).to be <= 10
    expect(Zlib::Inflate.inflate(result.output)).to eq(input)
  end

  it 'still completes bounded searches within a larger budget' do
    input = Array.new(200_000) { |index| (index * 73 + (index * index / 13)) % 256 }.pack('C*')
    result = optimal(input, budget: 5000)

    expect(result.diagnostics[:search]).to eq(:bounded)
    expect(result.diagnostics[:complete]).to be(true)
    expect(Zlib::Inflate.inflate(result.output)).to eq(input)
  end

  it 'preserves the default fast compression behavior' do
    input = random_bytes(1000, 99)

    expect(Zlib::Deflate.deflate(input)).to eq(Zlib::Deflate.deflate(input))
    expect(Zlib::Deflate.deflate(input, Zlib::BEST_SPEED)).not_to eq(
      optimal(input).output
    )
  end

  it 'rejects a non-positive search budget' do
    expect { optimal('abc', budget: 0) }.to raise_error(ArgumentError)
  end
end

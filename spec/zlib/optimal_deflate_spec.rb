# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'Rbzlib.optimal_deflate' do
  def roundtrip(raw)
    Zlib::Inflate.new(-MAX_WBITS).inflate(raw)
  end

  it 'keeps the existing Zlib::Deflate.deflate fast path unchanged' do
    input = 'abcabc' * 100
    expect(Zlib::Deflate.deflate(input, 9).bytes).to eq(
      [120, 218, 75, 76, 74, 78, 28, 69, 163, 136, 218, 8, 0, 173, 163, 229, 177]
    )
  end

  it 'encodes empty, fixed, dynamic and stored blocks and validates actual bit costs' do
    random = Random.new(1).bytes(100)
    repeated = ('abcdefghij' * 600)
    {
      empty: '',
      fixed: 'hello ' * 10,
      dynamic: repeated,
      stored: random
    }.each do |name, input|
      result = Rbzlib.optimal_deflate(input, exhaustive: name == :dynamic,
                                      exhaustive_max_bytes: 5_000, budget: 20_000)

      expect(roundtrip(result.string)).to eq(input.b)
      expect(result.diagnostic[:search_completed]).to be(true)
      expect(result.diagnostic[:selected_search]).to eq('exhaustive')
      if input.empty?
        expect(result.string.bytesize).to eq(2)
      else
        expect(result.diagnostic[:blocks]).to be >= 1
      end
    end

    expect(Rbzlib.optimal_deflate(repeated, budget: 20_000).diagnostic[:block_types]).to include(:dynamic)
    expect(Rbzlib.optimal_deflate(random).diagnostic[:block_types]).to eq(stored: 1)
  end

  it 'can split blocks without resetting the LZ77 window', :slow do
    random = Random.new(7).bytes(100)
    input = ('A' * 30_000) +
      ((100...40_100).map { |i| random[(i - 100) % 100].chr }.join) +
      ('A' * 30_000)

    result = Rbzlib.optimal_deflate(input, budget: 20_000)

    expect(roundtrip(result.string)).to eq(input.b)
    expect(result.diagnostic[:blocks]).to be > 1
    expect(result.diagnostic[:cross_block_references]).to be > 0
    expect(result.diagnostic[:search_completed]).to be(true)
  end

  it 'reports bounded search diagnostics under a restrictive calculation budget' do
    input = Random.new(4).bytes(200_000)
    result = Rbzlib.optimal_deflate(input, budget: 6)

    expect(roundtrip(result.string)).to eq(input.b)
    expect(result.diagnostic[:selected_search]).to eq('bounded')
    expect(result.diagnostic[:dynamic_tree_evaluations]).to be <= 6
    expect(result.diagnostic[:search_completed]).to be(false)
    expect(result.diagnostic).to include(
      budget: 6
    )
  end

  it 'returns the same exhaustive and bounded answer for short input and wraps zlib output' do
    input = Random.new(9).bytes(48)
    raw = Rbzlib.optimal_deflate(input, exhaustive: true, budget: 100_000)
    bounded = Rbzlib.optimal_deflate(input, budget: 10_000)
    wrapped = Zlib::Deflate.optimal_deflate(input)

    expect(bounded.string).to eq(raw.string)
    expect(Zlib::Inflate.inflate(wrapped.string)).to eq(input)
    expect(wrapped.diagnostic[:wrap]).to eq('zlib')
  end
end

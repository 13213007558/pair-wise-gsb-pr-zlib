# frozen_string_literal: true

########################################################################
# gzip_index_spec.rb
#
# Spec for the Zlib::GzipIndex class (random-access index for gzip files).
########################################################################
require 'spec_helper'
require 'tmpdir'
require 'fileutils'
require 'stringio'

RSpec.describe Zlib::GzipIndex do
  # Compress +parts+ into a single gzip member, ending a deflate block
  # after each part so the stream has plenty of block boundaries.
  def gzip_with_blocks(parts)
    io = StringIO.new(''.b)
    gz = Zlib::GzipWriter.new(io)
    parts.each do |part|
      gz.write(part)
      gz.flush
    end
    gz.close
    io.string
  end

  # Build a gzip stream out of stored (uncompressed) deflate blocks by
  # hand, since pr-zlib's own deflater cannot produce level-0 streams.
  def stored_gzip(data, block_size = 8192)
    out = +''.b
    out << [0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255].pack('C*')
    offset = 0
    loop do
      chunk = data.byteslice(offset, block_size) || ''.b
      final = offset + chunk.bytesize >= data.bytesize ? 1 : 0
      out << [final].pack('C')
      out << [chunk.bytesize, chunk.bytesize ^ 0xffff].pack('vv')
      out << chunk
      offset += chunk.bytesize
      break if offset >= data.bytesize
    end
    out << [Zlib.crc32(data), data.bytesize & 0xffffffff].pack('VV')
    out
  end

  before(:all) do
    @tmp_dir = Dir.mktmpdir('gzip_index_spec')

    rng = Random.new(20261002)
    words = ('aaa'..'zzz').to_a.sample(300, random: rng)
    @parts = Array.new(15) { Array.new(1500) { words.sample(random: rng) }.join(' ') }
    @data = @parts.join

    @gz_path = File.join(@tmp_dir, 'blocks.gz')
    File.binwrite(@gz_path, gzip_with_blocks(@parts))

    @stored_path = File.join(@tmp_dir, 'stored.gz')
    File.binwrite(@stored_path, stored_gzip(@data))

    first = @parts[0, 8].join
    rest = @parts[8..-1].join
    @member_boundary = first.bytesize
    @members_path = File.join(@tmp_dir, 'members.gz')
    File.binwrite(@members_path, gzip_with_blocks([first]) + stored_gzip(rest))

    @span = 4096
  end

  after(:all) do
    FileUtils.remove_entry(@tmp_dir) if @tmp_dir && File.exist?(@tmp_dir)
  end

  let(:index) { described_class.build(@gz_path, span: @span) }

  describe '.build' do
    it 'records checkpoints at block boundaries at least span bytes apart' do
      expect(index.points.length).to be > 4
      outputs = index.points.map(&:output)
      expect(outputs).to eq(outputs.sort)
      outputs.each_cons(2) do |a, b|
        expect(b - a).to be >= @span
      end
    end

    it 'starts with a checkpoint at the origin' do
      first = index.points.first
      expect(first.output).to eq(0)
      expect(first.input).to eq(0)
      expect(first.bits).to eq(0)
      expect(first.window).to be_empty
    end

    it 'stores bit state and a 32KB-capped history window per checkpoint' do
      index.points.each do |point|
        expect(point.bits).to be_between(0, 7)
        expect(point.window.bytesize).to eq([point.output, 32768].min)
      end
    end

    it 'captures checkpoints that are not byte aligned' do
      # Exercises the inflatePrime resume path when reading.
      expect(index.points.count { |p| p.bits != 0 }).to be > 0
    end

    it 'records content size, crc32 and member count' do
      expect(index.content_size).to eq(@data.bytesize)
      expect(index.content_crc32).to eq(Zlib.crc32(@data))
      expect(index.members).to eq(1)
    end

    it 'rejects an invalid span' do
      expect { described_class.build(@gz_path, span: 0) }.to raise_error(ArgumentError)
      expect { described_class.build(@gz_path, span: -5) }.to raise_error(ArgumentError)
    end

    it 'raises Zlib::DataError when compressed data is corrupt' do
      corrupt = File.binread(@gz_path).dup
      mid = corrupt.bytesize / 2
      corrupt.setbyte(mid, corrupt.getbyte(mid) ^ 0xff)
      path = File.join(@tmp_dir, 'corrupt.gz')
      File.binwrite(path, corrupt)
      expect { described_class.build(path, span: @span) }.to raise_error(Zlib::DataError)
    end

    it 'raises Zlib::DataError when the trailer crc is corrupt' do
      corrupt = File.binread(@gz_path).dup
      tail = corrupt.bytesize - 5
      corrupt.setbyte(tail, corrupt.getbyte(tail) ^ 0xff)
      path = File.join(@tmp_dir, 'corrupt_trailer.gz')
      File.binwrite(path, corrupt)
      expect { described_class.build(path, span: @span) }.to raise_error(Zlib::DataError)
    end

    it 'raises GzipIndex::Error for a truncated file' do
      path = File.join(@tmp_dir, 'truncated.gz')
      File.binwrite(path, File.binread(@gz_path)[0, 1000])
      expect { described_class.build(path, span: @span) }.to raise_error(Zlib::GzipIndex::Error)
    end
  end

  describe 'random access reads' do
    it 'matches sequential decompression around every checkpoint' do
      index.open(@gz_path) do |reader|
        index.points.each do |point|
          (-2..2).each do |delta|
            offset = point.output + delta
            next if offset.negative?
            expected = @data.byteslice(offset, 200) || ''
            expect(reader.read_at(offset, 200)).to eq(expected),
              "mismatch at offset #{offset} near checkpoint #{point.output}"
          end
        end
      end
    end

    it 'matches sequential decompression for reads spanning checkpoints' do
      index.open(@gz_path) do |reader|
        index.points.each do |point|
          length = 3 * @span
          expected = @data.byteslice(point.output, length) || ''
          expect(reader.read_at(point.output, length)).to eq(expected)
        end
      end
    end

    it 'reads the whole stream like a sequential GzipReader' do
      sequential = File.open(@gz_path, 'rb') { |io| Zlib::GzipReader.new(io).read }
      expect(sequential).to eq(@data)
      index.open(@gz_path) do |reader|
        expect(reader.read_at(0, index.content_size)).to eq(sequential)
      end
    end

    it 'returns a short read at the end of the stream' do
      index.open(@gz_path) do |reader|
        expect(reader.read_at(index.content_size - 3, 100)).to eq(@data[-3, 100])
      end
    end

    it 'returns an empty string beyond the end of the stream' do
      index.open(@gz_path) do |reader|
        expect(reader.read_at(index.content_size, 10)).to eq('')
        expect(reader.read_at(index.content_size + 1000, 10)).to eq('')
      end
    end

    it 'returns an empty string for a zero-length read' do
      index.open(@gz_path) do |reader|
        expect(reader.read_at(100, 0)).to eq('')
      end
    end

    it 'raises ArgumentError for negative offset or length' do
      index.open(@gz_path) do |reader|
        expect { reader.read_at(-1, 10) }.to raise_error(ArgumentError)
        expect { reader.read_at(0, -1) }.to raise_error(ArgumentError)
      end
    end

    it 'raises GzipIndex::Error when the reader is closed' do
      reader = index.open(@gz_path)
      reader.close
      expect { reader.read_at(0, 10) }.to raise_error(Zlib::GzipIndex::Error)
    end

    it 'reads stored (uncompressed) block streams around every checkpoint' do
      stored = described_class.build(@stored_path, span: @span)
      stored.open(@stored_path) do |reader|
        stored.points.each do |point|
          (-2..2).each do |delta|
            offset = point.output + delta
            next if offset.negative?
            expected = @data.byteslice(offset, 200) || ''
            expect(reader.read_at(offset, 200)).to eq(expected)
          end
        end
        expect(reader.read_at(0, stored.content_size)).to eq(@data)
      end
    end

    it 'reads concatenated gzip members, including across the boundary' do
      members = described_class.build(@members_path, span: @span)
      expect(members.members).to eq(2)
      members.open(@members_path) do |reader|
        expect(reader.read_at(0, members.content_size)).to eq(@data)
        expect(reader.read_at(@member_boundary - 100, 200))
          .to eq(@data.byteslice(@member_boundary - 100, 200))
        members.points.select { |p| p.output > @member_boundary }.each do |point|
          expect(reader.read_at(point.output, 150))
            .to eq(@data.byteslice(point.output, 150))
        end
      end
    end
  end

  describe 'source identity' do
    it 'accepts the file it was built for' do
      expect(index.valid_for?(@gz_path)).to be(true)
    end

    it 'rejects the file after it is modified' do
      path = File.join(@tmp_dir, 'mutable.gz')
      File.binwrite(path, File.binread(@gz_path))
      mutable = described_class.build(path, span: @span)
      expect(mutable.valid_for?(path)).to be(true)

      File.open(path, 'ab') { |fh| fh.write('x') }
      expect(mutable.valid_for?(path)).to be(false)
      expect { mutable.open(path) }.to raise_error(Zlib::GzipIndex::StaleIndexError)
    end

    it 'rejects the file after it is rewritten' do
      path = File.join(@tmp_dir, 'rewritten.gz')
      File.binwrite(path, File.binread(@gz_path))
      mutable = described_class.build(path, span: @span)

      File.binwrite(path, stored_gzip('different content'))
      expect(mutable.valid_for?(path)).to be(false)
      expect { mutable.open(path) }.to raise_error(Zlib::GzipIndex::StaleIndexError)
    end

    it 'rejects a missing file' do
      expect(index.valid_for?(File.join(@tmp_dir, 'missing.gz'))).to be(false)
    end
  end

  describe 'save and load' do
    it 'round-trips through a serialized index file' do
      index_path = File.join(@tmp_dir, 'blocks.gz.gzi')
      index.save(index_path)
      loaded = described_class.load(index_path)

      expect(loaded.points.length).to eq(index.points.length)
      expect(loaded.content_size).to eq(index.content_size)
      expect(loaded.content_crc32).to eq(index.content_crc32)
      expect(loaded.members).to eq(index.members)
      expect(loaded.valid_for?(@gz_path)).to be(true)

      loaded.open(@gz_path) do |reader|
        loaded.points.each do |point|
          expected = @data.byteslice(point.output, 128) || ''
          expect(reader.read_at(point.output, 128)).to eq(expected)
        end
      end
    end

    it 'raises CorruptIndexError for a file that is not an index' do
      path = File.join(@tmp_dir, 'not_an_index.gzi')
      File.binwrite(path, 'garbage')
      expect { described_class.load(path) }.to raise_error(Zlib::GzipIndex::CorruptIndexError)
    end
  end

  describe 'CRC verification reporting' do
    it 'reports whole-stream verification separately from partial reads' do
      expect(index.fully_verified?).to be(true)
      report = index.verification
      expect(report[:scope]).to eq(:full_stream)
      expect(report[:verified]).to be(true)
      expect(report[:crc32]).to eq(Zlib.crc32(@data))
      expect(report[:size]).to eq(@data.bytesize)
      expect(report[:members]).to eq(1)
    end

    it 'reports the exact scope of a partial read without claiming the stream' do
      index.open(@gz_path) do |reader|
        reader.read_at(1000, 500)
        report = reader.last_verification
        expect(report[:scope]).to eq(:partial)
        expect(report[:range]).to eq(1000...1500)
        expect(report[:crc32]).to eq(Zlib.crc32(@data.byteslice(1000, 500)))
        expect(report).not_to have_key(:crc_matches)
        # The stream-level report is untouched by partial reads.
        expect(index.verification[:scope]).to eq(:full_stream)
      end
    end

    it 'upgrades to full-stream scope only when a read covers everything' do
      index.open(@gz_path) do |reader|
        reader.read_at(0, index.content_size)
        report = reader.last_verification
        expect(report[:scope]).to eq(:full_stream)
        expect(report[:crc_matches]).to be(true)
      end
    end

    it 're-verifies the whole stream on demand with verify!' do
      report = index.verify!(@gz_path)
      expect(report[:scope]).to eq(:full_stream)
      expect(report[:verified]).to be(true)
    end

    it 'refuses to verify a changed file' do
      path = File.join(@tmp_dir, 'changed.gz')
      File.binwrite(path, File.binread(@gz_path))
      changed = described_class.build(path, span: @span)
      File.open(path, 'ab') { |fh| fh.write('x') }
      expect { changed.verify!(path) }.to raise_error(Zlib::GzipIndex::StaleIndexError)
    end
  end
end

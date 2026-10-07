# frozen_string_literal: true

########################################################################
# gzip_index_spec.rb
#
# Spec for the Zlib::GzipIndex random access index and reader.
########################################################################
require 'spec_helper'
require 'tmpdir'
require 'fileutils'

RSpec.describe Zlib::GzipIndex do
  # Build one gzip member (header + raw deflate stream + trailer) using
  # pr-zlib itself. +flush_every+ forces a deflate block boundary (and a
  # checkpoint opportunity) after every chunk; +flush+ selects the flush
  # mode used for those chunks.
  def gzip_member(data, level: 6, flush_every: 3000, flush: Zlib::SYNC_FLUSH)
    data = data.b
    deflate = Zlib::Deflate.new(level, -15)
    body = ''.b
    offset = 0
    while offset < data.bytesize
      body << deflate.deflate(data.byteslice(offset, flush_every), flush)
      offset += flush_every
    end
    body << deflate.deflate('', Zlib::FINISH)
    header = "\x1f\x8b\x08\x00".b + [0].pack('V') + "\x00\x03".b
    crc = Rbzlib.crc32(0, data)
    header + body + [crc, data.bytesize % (1 << 32)].pack('VV')
  end

  before(:all) do
    @dir = Dir.mktmpdir('pr-zlib-gzip-index')
    @gz_path = File.join(@dir, 'test.gz')
    @idx_path = File.join(@dir, 'test.gz.idx')

    rng = Random.new(1234)
    # Repetitive text: dense back-references that must resolve through the
    # 32KB history window saved in each checkpoint.
    @member_a = (0...40_000).map { |i| ((i % 211) + 32).chr }.join.b
    # Incompressible random data, stored blocks (level 0).
    @member_b = (0...20_000).map { rng.bytes(64) }.join.b[0, 20_000]
    # Mixed content with full flushes that reset the deflate history.
    @member_c = ((0...12_000).map { |i| ((i % 97) + 32).chr }.join +
                 rng.bytes(13_000)).b

    @data = @member_a + @member_b + @member_c
    gz = gzip_member(@member_a) +
         gzip_member(@member_b, level: 0) +
         gzip_member(@member_c, level: 1, flush_every: 4000, flush: Zlib::FULL_FLUSH)
    File.binwrite(@gz_path, gz)
    @stat = File.stat(@gz_path)
    @index = described_class.build(@gz_path, span: 6000)
  end

  after(:all) do
    FileUtils.remove_entry(@dir) if @dir && File.exist?(@dir)
  end

  describe '.build' do
    it 'records one member per gzip member' do
      expect(@index.members.size).to eq(3)
      expect(@index.members.map(&:out_offset)).to eq(
        [0, @member_a.bytesize, @member_a.bytesize + @member_b.bytesize]
      )
    end

    it 'records the total uncompressed size' do
      expect(@index.uncompressed_size).to eq(@data.bytesize)
    end

    it 'creates sorted checkpoints, one at every member start' do
      outs = @index.checkpoints.map(&:out_offset)
      expect(outs).to eq(outs.sort)
      @index.members.each do |member|
        checkpoint = @index.checkpoints.find { |c| c.out_offset == member.out_offset }
        expect(checkpoint).not_to be_nil
        expect(checkpoint.window).to be_empty
        expect(checkpoint.bits).to eq(0)
      end
    end

    it 'stores a history window of at most 32KB per checkpoint' do
      expect(@index.checkpoints.size).to be > 3
      @index.checkpoints.each do |checkpoint|
        expect(checkpoint.window.bytesize).to be <= 32_768
        expect(checkpoint.bits).to be_between(0, 7)
      end
    end

    it 'rejects a file that is not gzip' do
      plain = File.join(@dir, 'plain.txt')
      File.binwrite(plain, 'not a gzip file at all')
      expect { described_class.build(plain) }.to raise_error(Zlib::GzipIndex::FormatError)
    end

    it 'rejects a truncated gzip file' do
      truncated = File.join(@dir, 'truncated.gz')
      File.binwrite(truncated, File.binread(@gz_path)[0, 100])
      expect { described_class.build(truncated) }.to raise_error(Zlib::GzipIndex::TruncatedError)
    end
  end

  describe 'random access reads' do
    before(:all) do
      @reader = @index.reader_for(@gz_path)
    end

    after(:all) do
      @reader.close
    end

    it 'reads the whole file sequentially' do
      expect(@reader.read(0, @data.bytesize)).to eq(@data)
    end

    it 'reads to the end when length is omitted' do
      expect(@reader.read(@member_a.bytesize)).to eq(@data.byteslice(@member_a.bytesize..-1))
    end

    it 'returns an empty string for a zero length read' do
      expect(@reader.read(100, 0)).to eq('')
    end

    it 'clamps reads running past the end of the uncompressed data' do
      expect(@reader.read(@data.bytesize - 10, 500)).to eq(@data.byteslice(-10, 10))
      expect(@reader.read(@data.bytesize, 500)).to eq('')
    end

    it 'matches sequential decompression byte for byte around every checkpoint' do
      @index.checkpoints.each do |checkpoint|
        (-3..3).each do |delta|
          offset = checkpoint.out_offset + delta
          next if offset.negative? || offset >= @data.bytesize

          [1, 2, 3, 8].each do |length|
            length = [length, @data.bytesize - offset].min
            expect(@reader.read(offset, length)).to(
              eq(@data.byteslice(offset, length)),
              "mismatch at checkpoint out=#{checkpoint.out_offset} delta=#{delta} length=#{length}"
            )
          end
        end
      end
    end

    it 'matches sequential decompression for random offsets and lengths' do
      rng = Random.new(99)
      150.times do
        offset = rng.rand(@data.bytesize)
        length = [rng.rand(1..600), @data.bytesize - offset].min
        expect(@reader.read(offset, length)).to eq(@data.byteslice(offset, length))
      end
    end

    it 'reads across gzip member boundaries' do
      [@member_a.bytesize, @member_a.bytesize + @member_b.bytesize].each do |boundary|
        (-1..1).each do |delta|
          offset = boundary + delta - 10
          expect(@reader.read(offset, 21)).to eq(@data.byteslice(offset, 21))
        end
      end
    end
  end

  describe 'save and load' do
    it 'round-trips through a file and reads identically' do
      @index.save(@idx_path)
      loaded = described_class.load(@idx_path)
      expect(loaded.uncompressed_size).to eq(@data.bytesize)
      expect(loaded.checkpoints.size).to eq(@index.checkpoints.size)

      reader = loaded.reader_for(@gz_path)
      begin
        expect(reader.read(12_345, 2345)).to eq(@data.byteslice(12_345, 2345))
        expect(reader.read(0, @data.bytesize)).to eq(@data)
      ensure
        reader.close
      end
    end

    it 'rejects a file that is not a serialized index' do
      expect { described_class.load(@gz_path) }.to raise_error(Zlib::GzipIndex::FormatError)
    end
  end

  describe 'source identity binding' do
    it 'accepts the file the index was built for' do
      expect(@index.source_changed?(@gz_path)).to be(false)
      expect(@index.verify_source!(@gz_path)).to be(true)
    end

    it 'refuses to use the index after the file content changed' do
      changed = File.join(@dir, 'changed.gz')
      FileUtils.cp(@gz_path, changed)
      index = described_class.build(changed)
      File.open(changed, 'r+b') { |f| f.seek(50); f.write('X') }

      expect(index.source_changed?(changed)).to be(true)
      expect { index.verify_source!(changed) }.to raise_error(Zlib::GzipIndex::SourceChangedError)
      expect { index.reader_for(changed) }.to raise_error(Zlib::GzipIndex::SourceChangedError)
    end

    it 'refuses to use the index after the file was replaced' do
      replaced = File.join(@dir, 'replaced.gz')
      FileUtils.cp(@gz_path, replaced)
      index = described_class.build(replaced)
      File.binwrite(replaced, 'totally different contents')
      expect { index.verify_source!(replaced) }.to raise_error(Zlib::GzipIndex::SourceChangedError)
    end

    it 'detects content changes that preserve size and mtime only in strict mode' do
      sneaky = File.join(@dir, 'sneaky.gz')
      FileUtils.cp(@gz_path, sneaky)
      index = described_class.build(sneaky)
      stat = File.stat(sneaky)

      File.open(sneaky, 'r+b') { |f| f.seek(60); f.write('Q') }
      File.utime(stat.atime, stat.mtime, sneaky)

      expect(index.source_changed?(sneaky)).to be(false)
      expect(index.source_changed?(sneaky, strict: true)).to be(true)
      expect { index.verify_source!(sneaky, strict: true) }
        .to raise_error(Zlib::GzipIndex::SourceChangedError)
    end
  end

  describe 'CRC verification reporting' do
    before(:all) do
      @report_reader = @index.reader_for(@gz_path)
    end

    after(:all) do
      @report_reader.close
    end

    it 'never claims whole-file integrity from a partial read' do
      @report_reader.read(100, 50)
      report = @report_reader.last_report
      expect(report).to be_a(Zlib::GzipIndex::ReadReport)
      expect(report.full_file?).to be(false)
      expect(report.crc_verified?).to be(false)
      expect(report.members_verified).to be_empty
      expect(report.to_s).to include('NOT established')
    end

    it 'verifies CRC32 and ISIZE for members fully covered by a read' do
      @report_reader.read(0, @member_a.bytesize)
      report = @report_reader.last_report
      expect(report.members_verified).to eq([0])
      expect(report.crc_verified?).to be(true)
      expect(report.full_file?).to be(false)
    end

    it 'verifies the whole file with #verify and reports full scope' do
      report = @report_reader.verify
      expect(report).to be_a(Zlib::GzipIndex::IntegrityReport)
      expect(report.full_file?).to be(true)
      expect(report.ok?).to be(true)
      expect(report.members_verified).to eq([0, 1, 2])
      expect(report.uncompressed_size).to eq(@data.bytesize)
    end

    context 'with a corrupted CRC trailer' do
      before(:all) do
        @corrupt_path = File.join(@dir, 'corrupt.gz')
        FileUtils.cp(@gz_path, @corrupt_path)
        index = described_class.build(@corrupt_path)
        @corrupt_stat = File.stat(@corrupt_path)
        # Flip a bit in the CRC32 of the last member's trailer.
        File.open(@corrupt_path, 'r+b') do |f|
          f.seek(-6, IO::SEEK_END)
          f.write((f.read(1).ord ^ 0xff).chr)
        end
        File.utime(@corrupt_stat.atime, @corrupt_stat.mtime, @corrupt_path)
        @corrupt_reader = index.reader_for(@corrupt_path)
      end

      after(:all) do
        @corrupt_reader.close
      end

      it 'fails full verification and reports the CRC error' do
        report = @corrupt_reader.verify
        expect(report.full_file?).to be(true)
        expect(report.ok?).to be(false)
        expect(report.errors.join).to match(/crc error/i)
        expect { @corrupt_reader.verify! }.to raise_error(Zlib::GzipFile::Error)
      end

      it 'still reads intact members without claiming whole-file integrity' do
        data = @corrupt_reader.read(0, @member_a.bytesize)
        expect(data).to eq(@member_a)
        report = @corrupt_reader.last_report
        expect(report.crc_verified?).to be(true)
        expect(report.full_file?).to be(false)
      end
    end
  end
end

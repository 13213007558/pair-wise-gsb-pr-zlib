# frozen_string_literal: true

module Rbzlib
  OptimalResult = Struct.new(:output, :diagnostics, keyword_init: true)
  OptimalToken = Struct.new(:distance, :length, keyword_init: true)

  class OptimalLzParser
    include Rbzlib

    WINDOW_SIZE = 1 << MAX_WBITS
    HASH_BITS = DEF_MEM_LEVEL + 7
    HASH_SIZE = 1 << HASH_BITS
    HASH_MASK = HASH_SIZE - 1
    HASH_SHIFT = (HASH_BITS + MIN_MATCH - 1) / MIN_MATCH
    MAX_CHAIN = 4096
    NIL_POSITION = -1

    def initialize(input)
      @input = input.b
      @head = Array.new(HASH_SIZE, NIL_POSITION)
      @previous = Array.new(WINDOW_SIZE, NIL_POSITION)
      @hash = 0
    end

    def parse
      tokens = []
      position = 0
      already_inserted = false
      pending_candidate = NIL_POSITION

      while position < @input.length
        candidate = insert(position) unless already_inserted
        candidate = pending_candidate if already_inserted
        already_inserted = false
        distance, length = match_at(position, candidate)

        if length < MIN_MATCH
          tokens << OptimalToken.new(distance: 0, length: @input.getbyte(position))
          position += 1
          next
        end

        pending_candidate = insert(position + 1)
        next_distance, next_length = match_at(position + 1, pending_candidate)

        if next_distance.positive? && next_length > length
          tokens << OptimalToken.new(distance: 0, length: @input.getbyte(position))
          position += 1
          already_inserted = true
          next
        end

        tokens << OptimalToken.new(distance: distance, length: length)
        (position + 2...position + length).each { |offset| insert(offset) }
        position += length
      end

      tokens
    end

    private

    def insert(position)
      return NIL_POSITION if position + 2 >= @input.length

      @hash = hash_at(position)
      candidate = @head[@hash]
      @previous[position & (WINDOW_SIZE - 1)] = candidate
      @head[@hash] = position
      candidate
    end

    def hash_at(position)
      hash = @input.getbyte(position)
      hash = ((hash << HASH_SHIFT) ^ @input.getbyte(position + 1)) & HASH_MASK
      ((hash << HASH_SHIFT) ^ @input.getbyte(position + 2)) & HASH_MASK
    end

    def match_at(position, candidate)
      return [0, MIN_MATCH - 1] if position + MIN_MATCH > @input.length || candidate.nil? || candidate < 0

      minimum = [0, position - (WINDOW_SIZE - MIN_LOOKAHEAD)].max
      chain = MAX_CHAIN
      best_distance = 0
      best_length = MIN_MATCH - 1
      maximum = [MAX_MATCH, @input.length - position].min

      while candidate >= minimum && chain.positive?
        length = compare(candidate, position, maximum)
        if length > best_length
          best_length = length
          best_distance = position - candidate
          break if best_length == maximum
        end

        candidate = @previous[candidate & (WINDOW_SIZE - 1)]
        chain -= 1
      end

      if best_length == MIN_MATCH && best_distance > TOO_FAR
        best_distance = 0
        best_length = MIN_MATCH - 1
      end

      [best_distance, best_length]
    end

    def compare(candidate, position, maximum)
      length = 0
      while length < maximum &&
            @input.getbyte(candidate + length) == @input.getbyte(position + length)
        length += 1
      end
      length
    end
  end

  class OptimalBitWriter
    def initialize
      @bytes = String.new(encoding: Encoding::BINARY)
      @buffer = 0
      @bits = 0
    end

    def write(value, bit_count)
      @buffer |= value << @bits
      @bits += bit_count
      while @bits >= 8
        @bytes << (@buffer & 0xff)
        @buffer >>= 8
        @bits -= 8
      end
    end

    def write_bytes(bytes)
      raise 'unbalanced bit writer' unless @bits.zero?
      @bytes << bytes
    end

    def align
      write(0, (8 - @bits) % 8)
      @bytes
    end

    def byte_align
      align
      @buffer = 0
      @bits = 0
    end

    def write_code(code, bit_count)
      write(code, bit_count)
    end
  end

  class OptimalHeaderState
    include Rbzlib

    attr_accessor :dyn_ltree, :dyn_dtree, :bl_tree, :pending_buf, :pending, :bi_buf, :bi_valid

    def initialize(literal_tree, distance_tree, bit_length_tree)
      @dyn_ltree = literal_tree
      @dyn_dtree = distance_tree
      @bl_tree = bit_length_tree
      @pending_buf = Bytef.new(0.chr * 4096)
      @pending = 0
      @bi_buf = 0
      @bi_valid = 0
    end

    def send_bits(value, bit_count)
      if @bi_valid > 16 - bit_count
        @bi_buf |= (value << @bi_valid)
        @bi_buf &= 0xffff
        @pending_buf[@pending] = @bi_buf & 0xff
        @pending += 1
        @pending_buf[@pending] = @bi_buf >> 8
        @pending += 1
        @bi_buf = value >> (16 - @bi_valid)
        @bi_valid += bit_count - 16
      else
        @bi_buf |= value << @bi_valid
        @bi_valid += bit_count
      end
    end

    def transfer_to(writer)
      @pending.times { |index| writer.write(@pending_buf[index], 8) }
      writer.write(@bi_buf, @bi_valid)
    end

    def send_all(lcodes, dcodes, blcodes)
      bl_order = Rbzlib.class_variable_get(:@@bl_order)
      send_bits(lcodes - 257, 5)
      send_bits(dcodes - 1, 5)
      send_bits(blcodes - 4, 4)
      (0...blcodes).each { |rank| send_bits(@bl_tree[bl_order[rank]].dl, 3) }
      Rbzlib.send(:send_tree, self, @dyn_ltree, lcodes - 1)
      Rbzlib.send(:send_tree, self, @dyn_dtree, dcodes - 1)
    end

  end

  class OptimalCostEvaluator
    include Rbzlib

    MAX_STORED_BYTES = 65_535

    def initialize(tokens)
      @tokens = tokens
      @fixed_payload = Array.new(tokens.length + 1, 0)
      @byte_offsets = Array.new(tokens.length + 1, 0)
      @occurrences = Array.new(L_CODES + D_CODES) { [] }
      tokens.each_with_index { |token, index| tally(token, index) }
    end

    def byte_offset(index)
      @byte_offsets[index]
    end

    def edge(start, finish, bit_offset = 0, dynamic: true)
      stored = stored_cost(start, finish, bit_offset)
      fixed = fixed_cost(start, finish)
      dynamic = dynamic ? dynamic_cost(start, finish) : nil
      { stored: stored, fixed: fixed, dynamic: dynamic }
    end

    private

    def tally(token, index)
      @byte_offsets[index + 1] = @byte_offsets[index]
      if token.distance.zero?
        @byte_offsets[index + 1] += 1
        @fixed_payload[index + 1] = @fixed_payload[index] + @@static_ltree[token.length].dl
        @occurrences[token.length] << index
        return
      end

      @byte_offsets[index + 1] += token.length
      length_code = @@_length_code[token.length - MIN_MATCH]
      distance_code = distance_code(token.distance)
      @occurrences[LITERALS + 1 + length_code] << index
      @occurrences[L_CODES + distance_code] << index
      @fixed_payload[index + 1] = @fixed_payload[index] +
        @@static_ltree[LITERALS + 1 + length_code].dl + @@extra_lbits[length_code] +
        @@static_dtree[distance_code].dl + @@extra_dbits[distance_code]
    end

    def stored_cost(start, finish, bit_offset)
      bytes = @byte_offsets[finish] - @byte_offsets[start]
      return nil if bytes > MAX_STORED_BYTES
      (8 - bit_offset) % 8 + 40 + bytes * 8
    end

    def fixed_cost(start, finish)
      3 + @fixed_payload[finish] - @fixed_payload[start] + @@static_ltree[END_BLOCK].dl
    end

    def dynamic_cost(start, finish)
      state = new_state
      @occurrences.each_with_index do |positions, symbol|
        frequency = count_occurrences(positions, start, finish)
        if symbol < L_CODES
          state.dyn_ltree[symbol].fc = frequency
        else
          state.dyn_dtree[symbol - L_CODES].fc = frequency
        end
      end
      state.dyn_ltree[END_BLOCK].fc = 1

      build_tree(state, state.l_desc)
      build_tree(state, state.d_desc)
      build_bl_tree(state)
      state.opt_len + 3
    end

    def count_occurrences(positions, start, finish)
      first = positions.bsearch_index { |position| position >= start } || positions.length
      after = positions.bsearch_index { |position| position >= finish } || positions.length
      after - first
    end

    def new_state
      state = Deflate_state.new
      state.dyn_ltree = Array.new(HEAP_SIZE) { Ct_data.new }
      state.dyn_dtree = Array.new(2 * D_CODES + 1) { Ct_data.new }
      state.bl_tree = Array.new(2 * BL_CODES + 1) { Ct_data.new }
      state.dyn_ltree.each { |node| node.fc = 0; node.dl = 0 }
      state.dyn_dtree.each { |node| node.fc = 0; node.dl = 0 }
      state.bl_tree.each { |node| node.fc = 0; node.dl = 0 }
      state.bl_count = Array.new(MAX_BITS + 1, 0)
      state.heap = Array.new(2 * L_CODES + 1, 0)
      state.depth = Array.new(2 * L_CODES + 1, 0)
      state.opt_len = 0
      state.static_len = 0
      state.l_desc = Tree_desc.new
      state.d_desc = Tree_desc.new
      state.bl_desc = Tree_desc.new
      state.l_desc.dyn_tree = state.dyn_ltree
      state.l_desc.stat_desc = @@static_l_desc
      state.d_desc.dyn_tree = state.dyn_dtree
      state.d_desc.stat_desc = @@static_d_desc
      state.bl_desc.dyn_tree = state.bl_tree
      state.bl_desc.stat_desc = @@static_bl_desc
      state
    end

    def distance_code(distance)
      value = distance - 1
      return @@_dist_code[value] if value < 256
      @@_dist_code[256 + (value >> 7)]
    end
  end

  class OptimalPlanner
    DEFAULT_BUDGET = 25_000

    def initialize(input, budget)
      @input = input.b
      @budget = budget
      raise ArgumentError, 'budget must be positive' unless budget.is_a?(Integer) && budget.positive?
      @tokens = OptimalLzParser.new(@input).parse
      @evaluator = OptimalCostEvaluator.new(@tokens)
    end

    def plan
      exact_edges = exhaustive_edge_count
      if exact_edges <= @budget
        run(:exhaustive, nil, @budget)
      else
        run(:bounded, bounded_boundaries, @budget)
      end
    end

    private

    def exhaustive_edge_count
      @tokens.length * (@tokens.length + 1) / 2
    end

    def bounded_boundaries
      boundaries = [0, @tokens.length]
      token_grid = [16, (@tokens.length * 32 / @budget)].max
      position = token_grid
      while position < @tokens.length
        boundaries << position
        position += token_grid
      end
      stored_boundaries.each { |value| boundaries << value }
      boundaries.uniq.sort
    end

    def stored_boundaries
      result = []
      boundary_bytes = 65_535
      while boundary_bytes < @input.length
        index = (1..@tokens.length).bsearch do |finish|
          @evaluator.byte_offset(finish) >= boundary_bytes
        end
        result << index if index
        boundary_bytes += 65_535
      end
      result
    end

    def run(search, boundaries, budget)
      boundaries ||= (0..@tokens.length).to_a
      states = Array.new(@tokens.length + 1)
      states[0] = Array.new(8)
      states[0][0] = { bits: 0, residue: 0, parent: nil, parent_residue: nil, type: nil }
      evaluations = 0
      complete = true

      boundaries[1..].each do |finish|
        eligible_starts(finish, boundaries).each do |start|
          next if states[start].nil? || states[start].compact.empty?

          allow_dynamic = search == :exhaustive || evaluations < budget
          states[start].each do |previous|
            next if previous.nil?
            edge = @evaluator.edge(start, finish, previous[:residue], dynamic: allow_dynamic)
            evaluate(states, start, finish, edge, previous)
          end
          evaluations += 1

          if !allow_dynamic
            complete = false
            break unless finish == @tokens.length
          end
        end
      end

      result(finish_state(states), states, evaluations, search, complete, budget)
    end

    def eligible_starts(finish, boundaries)
      starts = boundaries[0...-1].select do |start|
        start < finish
      end
      return starts if starts.length <= 32 || finish == @tokens.length

      degree = [[@budget / [boundaries.length - 1, 1].max, 1].max, 32].min
      step = starts.length.to_f / degree
      sampled = degree.times.map { |index| starts[(index * step).floor] }
      minimum_start = starts.bsearch do |start|
        @evaluator.byte_offset(finish) - @evaluator.byte_offset(start) <= 65_535
      end
      if minimum_start.nil? && starts.length > 1
        sampled.unshift(starts[-1])
      elsif minimum_start
        sampled.unshift(minimum_start)
      end
      sampled.compact.uniq
    end

    def evaluate(states, start, finish, edge, previous)
      states[finish] ||= Array.new(8)
      [
        [:stored, edge[:stored] && previous[:bits] + edge[:stored], 0],
        [:fixed, previous[:bits] + edge[:fixed], (previous[:residue] + edge[:fixed]) % 8],
        [:dynamic, edge[:dynamic] && previous[:bits] + edge[:dynamic],
         edge[:dynamic] && (previous[:residue] + edge[:dynamic]) % 8]
      ].each do |type, bits, residue|
        next if bits.nil?
        current = states[finish][residue]
        if current.nil? || bits < current[:bits] || (bits == current[:bits] && rank(type) < rank(current[:type]))
          states[finish][residue] = {
            bits: bits,
            residue: residue,
            parent: start,
            parent_residue: previous[:residue],
            type: type
          }
        end
      end
    end

    def rank(type)
      { stored: 0, fixed: 1, dynamic: 2 }.fetch(type)
    end

    def finish_state(states)
      candidates = states[@tokens.length].compact
      state = candidates.min_by { |candidate| candidate[:bits] + (8 - candidate[:residue]) % 8 }
      state.dup.tap { |result| result[:bits] += (8 - state[:residue]) % 8 }
    end

    def result(final_state, states, evaluations, search, complete, budget)
      blocks = []
      finish = @tokens.length
      reconstruction_states = states.map(&:dup)
      current_state = final_state
      while finish.positive?
        state = current_state
        blocks.unshift(start: state[:parent], finish: finish, type: state[:type])
        finish = state[:parent]
        residue = state[:parent_residue]
        next if finish.nil?
        current_state = reconstruction_states[finish][residue]
      end

      counts = Hash.new(0)
      blocks.each { |block| counts[block[:type]] += 1 }

      {
        search: search,
        complete: complete,
        exhaustive: search == :exhaustive,
        evaluations: evaluations,
        budget: budget,
        input_bytes: @input.length,
        tokens: @tokens.length,
        blocks: blocks,
        block_counts: counts,
        bit_cost: final_state[:bits],
        lz77_window_reset: false
      }
    end
  end

  class OptimalEmitter
    include Rbzlib

    def initialize(input, tokens, blocks)
      @input = input.b
      @tokens = tokens
      @blocks = blocks
      @writer = OptimalBitWriter.new
      @byte_offsets = Array.new(tokens.length + 1, 0)
      tokens.each_with_index do |token, index|
        @byte_offsets[index + 1] = @byte_offsets[index] + (token.distance.zero? ? 1 : token.length)
      end
    end

    def emit
      @blocks.each_with_index do |block, index|
        last = index == @blocks.length - 1
        send_block(block, last)
      end
      send_empty_fixed if @blocks.empty?
      @writer.align
    end

    private

    def byte_offset(index)
      @byte_offsets[index]
    end

    def send_empty_fixed
      @writer.write(1, 1)
      @writer.write(STATIC_TREES, 2)
      @writer.write_code(@@static_ltree[END_BLOCK].fc, @@static_ltree[END_BLOCK].dl)
    end

    def send_block(block, last)
      case block[:type]
      when :stored
        send_stored(block, last)
      when :fixed
        send_fixed(block, last)
      else
        send_dynamic(block, last)
      end
    end

    def send_stored(block, last)
      start = byte_offset(block[:start])
      finish = byte_offset(block[:finish])
      bytes = finish - start
      @writer.write(last ? 1 : 0, 1)
      @writer.write(STORED_BLOCK, 2)
      @writer.byte_align
      @writer.write(bytes, 16)
      @writer.write(~bytes & 0xffff, 16)
      @writer.write_bytes(@input[start, bytes])
    end

    def send_fixed(block, last)
      @writer.write(last ? 1 : 0, 1)
      @writer.write(STATIC_TREES, 2)
      @tokens[block[:start]...block[:finish]].each do |token|
        if token.distance.zero?
          @writer.write_code(@@static_ltree[token.length].fc, @@static_ltree[token.length].dl)
        else
          send_match(token, @@static_ltree, @@static_dtree)
        end
      end
      @writer.write_code(@@static_ltree[END_BLOCK].fc, @@static_ltree[END_BLOCK].dl)
    end

    def send_dynamic(block, last)
      literal_tree, distance_tree, bit_length_tree, literal_codes, distance_codes, bit_length_codes = build_trees(block)
      @writer.write(last ? 1 : 0, 1)
      @writer.write(DYN_TREES, 2)
      write_dynamic_header(literal_tree, distance_tree, bit_length_tree,
                           literal_codes, distance_codes, bit_length_codes)

      @tokens[block[:start]...block[:finish]].each do |token|
        if token.distance.zero?
          @writer.write_code(literal_tree[token.length].fc, literal_tree[token.length].dl)
        else
          send_match(token, literal_tree, distance_tree)
        end
      end
      @writer.write_code(literal_tree[END_BLOCK].fc, literal_tree[END_BLOCK].dl)
    end

    def write_dynamic_header(literal_tree, distance_tree, bit_length_tree,
                             literal_codes, distance_codes, bit_length_codes)
      state = OptimalHeaderState.new(literal_tree, distance_tree, bit_length_tree)
      state.send_all(literal_codes, distance_codes, bit_length_codes)
      state.transfer_to(@writer)
    end

    def send_match(token, literal_tree, distance_tree)
      stored_length = token.length - MIN_MATCH
      length_code = @@_length_code[stored_length]
      @writer.write_code(literal_tree[LITERALS + 1 + length_code].fc,
                         literal_tree[LITERALS + 1 + length_code].dl)
      extra = @@extra_lbits[length_code]
      @writer.write(stored_length - @@base_length[length_code], extra) if extra.positive?

      value = token.distance - 1
      distance_code = value < 256 ? @@_dist_code[value] : @@_dist_code[256 + (value >> 7)]
      @writer.write_code(distance_tree[distance_code].fc, distance_tree[distance_code].dl)
      extra = @@extra_dbits[distance_code]
      @writer.write(value - @@base_dist[distance_code], extra) if extra.positive?
    end

    def build_trees(block)
      literal_tree = Array.new(HEAP_SIZE) { Ct_data.new }
      distance_tree = Array.new(2 * D_CODES + 1) { Ct_data.new }
      bit_length_tree = Array.new(2 * BL_CODES + 1) { Ct_data.new }
      literal_tree.each { |node| node.fc = 0; node.dl = 0 }
      distance_tree.each { |node| node.fc = 0; node.dl = 0 }
      bit_length_tree.each { |node| node.fc = 0; node.dl = 0 }

      @tokens[block[:start]...block[:finish]].each do |token|
        if token.distance.zero?
          literal_tree[token.length].fc += 1
        else
          stored_length = token.length - MIN_MATCH
          literal_tree[LITERALS + 1 + @@_length_code[stored_length]].fc += 1
          distance_tree[distance_symbol(token.distance)].fc += 1
        end
      end
      literal_tree[END_BLOCK].fc = 1

      state = Deflate_state.new
      state.dyn_ltree = literal_tree
      state.dyn_dtree = distance_tree
      state.bl_tree = bit_length_tree
      state.bl_count = Array.new(MAX_BITS + 1, 0)
      state.heap = Array.new(2 * L_CODES + 1, 0)
      state.depth = Array.new(2 * L_CODES + 1, 0)
      state.opt_len = 0
      state.static_len = 0
      state.l_desc = Tree_desc.new
      state.d_desc = Tree_desc.new
      state.bl_desc = Tree_desc.new
      state.l_desc.dyn_tree = literal_tree
      state.l_desc.stat_desc = @@static_l_desc
      state.d_desc.dyn_tree = distance_tree
      state.d_desc.stat_desc = @@static_d_desc
      state.bl_desc.dyn_tree = bit_length_tree
      state.bl_desc.stat_desc = @@static_bl_desc

      build_tree(state, state.l_desc)
      build_tree(state, state.d_desc)
      max_bit_index = build_bl_tree(state)
      [
        literal_tree,
        distance_tree,
        bit_length_tree,
        state.l_desc.max_code + 1,
        state.d_desc.max_code + 1,
        max_bit_index + 1
      ]
    end

    def distance_symbol(distance)
      value = distance - 1
      return @@_dist_code[value] if value < 256
      @@_dist_code[256 + (value >> 7)]
    end
  end

  module_function

  def optimal_deflate(input, budget: OptimalPlanner::DEFAULT_BUDGET)
    input = input.to_s.dup.force_encoding(Encoding::BINARY)
    planner = OptimalPlanner.new(input, budget)
    tokens = planner.instance_variable_get(:@tokens)
    diagnostics = planner.plan
    raw = OptimalEmitter.new(input, tokens, diagnostics[:blocks]).emit
    checksum = adler32(adler32(0, nil), input, input.length)
    output = String.new("\x78\xda", encoding: Encoding::BINARY)
    output << raw
    output << [checksum].pack('N')
    OptimalResult.new(output: output, diagnostics: diagnostics)
  end

end

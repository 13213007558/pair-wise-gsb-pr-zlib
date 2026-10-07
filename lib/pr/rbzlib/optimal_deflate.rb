# frozen_string_literal: true

module Rbzlib
  OptimalDeflateResult = Struct.new(:string, :diagnostic, keyword_init: true)
  OptimalEdge = Struct.new(
    :from, :to, :start_token, :end_token, :bytes,
    :fixed_bits, :dynamic_bits, :stored_bits
  )
  OptimalTree = Struct.new(
    :lit_tree, :dist_tree, :bl_tree, :lit_max, :dist_max, :max_blindex, :header_bits
  )
  OptimalBackpointer = Struct.new(:boundary, :phase, :block_type)

  class OptimalBitWriter
    attr_reader :bytes
    attr_accessor :bit_count

    def initialize
      @bytes = String.new
      @buffer = 0
      @valid = 0
      @bit_count = 0
    end

    def write(value, length)
      @buffer |= (value << @valid)
      @valid += length
      @bit_count += length
      while @valid >= 8
        @bytes << (@buffer & 0xff)
        @buffer >>= 8
        @valid -= 8
      end
    end

    def align
      write(0, (8 - @valid) & 7)
    end


    def finish
      align
      @bytes.force_encoding(Encoding::BINARY)
    end
  end

  class << self
    OPTIMAL_CONFIGURATIONS = [
      nil,
      {max_chain: 4, lazy: false, max_lazy: 4},
      {max_chain: 8, lazy: false, max_lazy: 5},
      {max_chain: 32, lazy: false, max_lazy: 6},
      {max_chain: 16, lazy: true, max_lazy: 4},
      {max_chain: 32, lazy: true, max_lazy: 16},
      {max_chain: 128, lazy: true, max_lazy: 16},
      {max_chain: 256, lazy: true, max_lazy: 32},
      {max_chain: 1024, lazy: true, max_lazy: 128},
      {max_chain: 4096, lazy: true, max_lazy: 258}
    ].freeze

    def optimal_deflate(input, level: Z_BEST_COMPRESSION, window_bits: MAX_WBITS,
                        budget: 20_000, exhaustive: false,
                        exhaustive_max_bytes: 64)
      input = String(input)
      unless input.encoding.ascii_compatible?
        raise Encoding::CompatibilityError, 'input must be ASCII compatible'
      end
      raise ArgumentError, 'optimal deflate supports levels 1..9' unless level >= Z_BEST_SPEED && level <= Z_BEST_COMPRESSION
      raise ArgumentError, "window_bits must be between 9 and #{MAX_WBITS}" unless window_bits >= 9 && window_bits <= MAX_WBITS
      raise ArgumentError, 'budget must be an integer of at least 6' unless budget.is_a?(Integer) && budget >= 6

      parsed = optimal_parse(input, level, window_bits).merge(level: level)
      if input.bytesize.zero?
        writer = OptimalBitWriter.new
        static = Rbzlib.optimal_static_trees[0][END_BLOCK]
        writer.write(1 | (STATIC_TREES << 1), 3)
        writer.write(static.fc, static.dl)
        output = writer.finish
        diagnostic = optimal_diagnostic(
          input, output,
          {tokens: [], match_evaluations: 0, level: level},
          {
            positions: [0], boundaries: [0], states: [[[0, nil]]], edges: [],
            used_evaluations: 0, exhaustive: true, exhaustive_requested: true,
            search_completed: true
          },
          budget, window_bits
        )
        return OptimalDeflateResult.new(string: output, diagnostic: diagnostic)
      end
      plan = optimal_plan(input, parsed[:tokens], budget,
                          exhaustive || input.bytesize <= exhaustive_max_bytes)
      output = optimal_encode(input, parsed[:tokens], plan)
      diagnostic = optimal_diagnostic(input, output, parsed, plan, budget, window_bits)
      OptimalDeflateResult.new(string: output, diagnostic: diagnostic)
    end

    private

    def optimal_configuration(level)
      OPTIMAL_CONFIGURATIONS[level]
    end

    def optimal_hash(input, position, mask)
      ((input.getbyte(position) << 10) ^
        (input.getbyte(position + 1) << 5) ^
        input.getbyte(position + 2)) & mask
    end

    def optimal_insert(input, position, head, previous_links, hash_size, mask)
      return nil if position + MIN_MATCH > input.bytesize

      key = optimal_hash(input, position, mask)
      previous = head[key]
      previous_links[position & mask] = previous
      head[key] = position
      previous
    end

    def optimal_match(input, position, head, previous_links, window_size, max_chain, match_evaluations)
      candidate = optimal_insert(input, position, head, previous_links, window_size, window_size - 1)
      max_length = [MAX_MATCH - 1, input.bytesize - position].min
      best_length = MIN_MATCH - 1
      best_distance = nil
      oldest = position > window_size ? position - window_size : 0

      while candidate && candidate >= oldest && max_chain.positive?
        max_chain -= 1
        match_evaluations << true
        length = 0
        while length < max_length && input.getbyte(candidate + length) == input.getbyte(position + length)
          length += 1
        end

        if length > best_length
          best_length = length
          best_distance = position - candidate
          break if best_length >= max_length
        end

        candidate = previous_links[candidate & (window_size - 1)]
      end

      best_length >= MIN_MATCH ? [best_distance, best_length] : nil
    end

    def optimal_parse(input, level, window_bits)
      window_size = 1 << window_bits
      head = Array.new(window_size, nil)
      previous_links = Array.new(window_size, nil)
      configuration = optimal_configuration(level)
      max_chain = configuration[:max_chain]
      tokens = []
      position = 0
      pending = nil
      match_evaluations = 0
      counter = []

      while position < input.bytesize
        counter.clear
        current = optimal_match(input, position, head, previous_links, window_size, max_chain, counter)
        match_evaluations += counter.length

        if pending
          start, pending_distance, pending_length = pending
          if current && current[1] > pending_length
            tokens << [:literal, input.getbyte(start), nil]
            pending = [position, current[0], current[1]]
            position += 1
          else
            tokens << [:match, pending_distance, pending_length]
            position = start + pending_length
            (start + 2...position).each do |inserted|
              optimal_insert(input, inserted, head, previous_links, window_size, window_size - 1)
            end
            pending = nil
          end
        elsif current
          distance, length = current
          if configuration[:lazy] && length < configuration[:max_lazy] &&
             position + length < input.bytesize
            pending = [position, distance, length]
            position += 1
          else
            tokens << [:match, distance, length]
            (position + 1...position + length).each do |inserted|
              optimal_insert(input, inserted, head, previous_links, window_size, window_size - 1)
            end
            position += length
          end
        else
          tokens << [:literal, input.getbyte(position), nil]
          position += 1
        end
      end

      if pending
        start, _distance, _length = pending
        tokens << [:literal, input.getbyte(start), nil]
      end

      {tokens: tokens, match_evaluations: match_evaluations}
    end

    def optimal_token_positions(tokens)
      positions = Array.new(tokens.length + 1, 0)
      offset = 0
      tokens.each_with_index do |token, index|
        offset += token[0] == :literal ? 1 : token[2]
        positions[index + 1] = offset
      end
      positions
    end

    def optimal_distance_code(distance)
      value = distance - 1
      if value < 256
        Rbzlib.optimal_dist_code[value]
      else
        Rbzlib.optimal_dist_code[256 + ((value >> 7) & 255)]
      end
    end

    def optimal_match_length_code(length)
      Rbzlib.optimal_length_code[length - MIN_MATCH]
    end

    def optimal_fixed_symbol_bits(token)
      type, value, length = token
      if type == :literal
        Rbzlib.optimal_static_trees[0][value].dl
      else
        length_code = optimal_match_length_code(length)
        static_length = Rbzlib.optimal_static_trees[0][LITERALS + 1 + length_code]
        static_length.dl +
        Rbzlib.optimal_extra_lbits[length_code] +
        Rbzlib.optimal_static_trees[1][optimal_distance_code(value)].dl +
          Rbzlib.optimal_extra_dbits[optimal_distance_code(value)]
      end
    end

    def optimal_tree_state
      Struct.new(:bl_count, :heap, :depth, :heap_len, :heap_max, :opt_len, :static_len,
                 :bl_tree, :bl_desc, :l_desc, :d_desc, :dyn_ltree, :dyn_dtree).new(
        Array.new(MAX_BITS + 1, 0),
        Array.new(HEAP_SIZE + L_CODES, 0),
        Array.new(HEAP_SIZE + L_CODES, 0),
        0,
        HEAP_SIZE,
        0,
        0,
        nil,
        nil,
        nil,
        nil,
        nil,
        nil
      )
    end

    def optimal_tree_descriptor(tree, static_tree, base, extra, elems, max_bits)
      Tree_desc.new(
        tree,
        0,
        Static_tree_desc.new(static_tree, extra, base, elems, max_bits)
      )
    end

    def optimal_code_length_operations(lengths, count)
      operations = []
      index = 0
      previous_length = -1
      next_length = lengths[0]
      current_count = 0
      max_count = 7
      min_count = 4

      max_count = 138 if next_length.zero?

      while index < count
        current_length = next_length
        next_length = index + 1 < count ? lengths[index + 1] : 0xffff
        current_count += 1

        if current_count < max_count && current_length == next_length
          index += 1
          next
        elsif current_count < min_count
          current_count.times { operations << current_length }
        elsif !current_length.zero?
          if current_length != previous_length
            operations << current_length
            current_count -= 1
          end
          operations << [REP_3_6, current_count - 3, 2] if current_count.positive?
        elsif current_count <= 10
          operations << [REPZ_3_10, current_count - 3, 3]
        else
          operations << [REPZ_11_138, current_count - 11, 7]
        end

        current_count = 0
        previous_length = current_length
        if next_length.zero?
          max_count = 138
          min_count = 3
        elsif current_length == next_length
          max_count = 6
          min_count = 3
        else
          max_count = 7
          min_count = 4
        end
        index += 1
      end
      operations
    end

    def optimal_build_tree(frequencies, static_tree, base, extra, elems, max_bits)
      work_tree = Array.new(2 * HEAP_SIZE) { Ct_data.new(0, 0) }
      frequencies.each_with_index { |frequency, index| work_tree[index].fc = frequency }
      tree = Array.new(elems + 1) { Ct_data.new(0, 0) }
      descriptor = optimal_tree_descriptor(tree, static_tree, base, extra, elems, max_bits)
      state = optimal_tree_state
      descriptor.dyn_tree = work_tree
      Rbzlib.build_tree(state, descriptor)
      (0...elems).each do |index|
        tree[index].fc = work_tree[index].fc
        tree[index].dl = work_tree[index].dl
      end
      [tree, descriptor.max_code]
    end

    def optimal_dynamic_tree(lit_freq, dist_freq)
      static_lit, static_dist = Rbzlib.optimal_static_trees
      lit_tree, lit_max = optimal_build_tree(
        lit_freq, static_lit, LITERALS + 1, Rbzlib.optimal_extra_lbits, L_CODES, MAX_BITS
      )
      dist_tree, dist_max = optimal_build_tree(
        dist_freq, static_dist, 0, Rbzlib.optimal_extra_dbits, D_CODES, MAX_BITS
      )

      bl_state = optimal_tree_state
      bl_state.bl_tree = Array.new(HEAP_SIZE + BL_CODES) { Ct_data.new(0, 0) }
      bl_state.bl_desc = optimal_tree_descriptor(
        bl_state.bl_tree, nil, 0, Rbzlib.optimal_extra_blbits, BL_CODES, MAX_BL_BITS
      )
      bl_state.l_desc = Tree_desc.new(lit_tree, lit_max, nil)
      bl_state.d_desc = Tree_desc.new(dist_tree, dist_max, nil)

      if bl_state.l_desc.max_code != lit_max
        Rbzlib.scan_tree(bl_state, lit_tree, bl_state.l_desc.max_code)
      else
        Rbzlib.scan_tree(bl_state, lit_tree, lit_max)
      end
      Rbzlib.scan_tree(bl_state, dist_tree, dist_max)
      Rbzlib.build_tree(bl_state, bl_state.bl_desc)

      max_blindex = (BL_CODES - 1).downto(3).find do |index|
        bl_state.bl_tree[Rbzlib.optimal_bl_order[index]].dl != 0
      end
      header_bits = 5 + 5 + 4 + (3 * (max_blindex + 1)) + bl_state.opt_len
      OptimalTree.new(
        lit_tree, dist_tree, bl_state.bl_tree,
        lit_max, dist_max, max_blindex, header_bits
      )
    end

    def optimal_build_snapshots(tokens, token_ids)
      lit = Array.new(L_CODES, 0)
      dist = Array.new(D_CODES, 0)
      fixed_bits = 0
      snapshots = []
      processed = 0

      token_ids.each do |token_id|
        while processed < token_id
          token = tokens[processed]
          fixed_bits += optimal_fixed_symbol_bits(token)
          if token[0] == :literal
            lit[token[1]] += 1
          else
            lit[LITERALS + 1 + optimal_match_length_code(token[2])] += 1
            dist[optimal_distance_code(token[1])] += 1
          end
          processed += 1
        end
        snapshots << {
          fixed_bits: fixed_bits,
          lit: lit.dup,
          dist: dist.dup
        }
      end

      snapshots.last[:lit][END_BLOCK] = 1
      snapshots
    end

    def optimal_boundary_token_ids(tokens, positions, exhaustive, budget)
      ids = [0]
      if exhaustive
        ids.concat(1.upto(tokens.length).to_a)
      else
        target_count = [[2, Integer.sqrt((2 * budget) / 3)].max, 2].max
        byte_step = [1, ((positions.last - 1).to_f / (target_count - 1)).ceil].max
        grid = 0
        token_index = 0
        while grid < positions.last
          grid += byte_step
          token_index += 1 while token_index < positions.length && positions[token_index] < grid
          ids << token_index if token_index < positions.length
        end

        forced = 0
        while forced < positions.last
          forced += 65_535
          token_index = 0
          token_index += 1 while token_index < positions.length && positions[token_index] < forced
          ids << token_index if token_index < positions.length
        end
        ids << tokens.length
      end
      ids.uniq.sort
    end

    def optimal_dynamic_payload_bits(lit_freq, dist_freq, tree)
      payload = 0
      lit_freq.each_with_index do |frequency, index|
        next if frequency.zero?
        length_index = index >= LITERALS + 1 ? index - (LITERALS + 1) : nil
        payload += frequency * tree.lit_tree[index].dl
        if index >= LITERALS + 1
          payload += frequency * Rbzlib.optimal_extra_lbits[length_index]
        end
      end
      dist_freq.each_with_index do |frequency, index|
        next if frequency.zero?
        payload += frequency * tree.dist_tree[index].dl
        payload += frequency * Rbzlib.optimal_extra_dbits[index]
      end
      payload
    end

    def optimal_make_edge(tokens, positions, snapshots, boundaries, from, to,
                          tree_evaluations_available)
      start_token = boundaries[from]
      end_token = boundaries[to]
      bytes = positions[end_token] - positions[start_token]
      fixed_bits = 3 + snapshots[to][:fixed_bits] - snapshots[from][:fixed_bits] + 7
      edge = OptimalEdge.new(
        from, to, start_token, end_token, bytes,
        fixed_bits, nil, nil
      )

      if bytes <= 65_535
        edge.stored_bits = 40 + (bytes * 8)
      end

      if tree_evaluations_available.positive?
        lit = snapshots[to][:lit].map.with_index { |value, index| value - snapshots[from][:lit][index] }
        dist = snapshots[to][:dist].map.with_index { |value, index| value - snapshots[from][:dist][index] }
        lit[END_BLOCK] += 1
        tree = optimal_dynamic_tree(lit, dist)
        edge.dynamic_bits = 3 + tree.header_bits + optimal_dynamic_payload_bits(lit, dist, tree)
      end

      edge
    end

    def optimal_plan(input, tokens, budget, exhaustive_requested)
      positions = optimal_token_positions(tokens)
      exhaustive = exhaustive_requested &&
        ((tokens.length + 1) * tokens.length / 2) <= budget
      token_ids = optimal_boundary_token_ids(tokens, positions, exhaustive, budget)
      snapshots = optimal_build_snapshots(tokens, token_ids)
      boundaries = token_ids
      edges = Array.new(boundaries.length) { [] }
      used_evaluations = 0
      skipped_dynamic = false
      search_completed = true

      add_edge = lambda do |from, to|
        tree_available = budget - used_evaluations
        if tree_available <= 0
          skipped_dynamic = true
          tree_available = 0
        end
        edge = optimal_make_edge(
          tokens, positions, snapshots, boundaries, from, to, tree_available
        )
        if edge.dynamic_bits
          used_evaluations += 1
        elsif tree_available <= 0
          skipped_dynamic = true
        end
        edges[to] << edge
        true
      end

      final_boundary_index = boundaries.length - 1
      add_edge.call(0, final_boundary_index) if final_boundary_index.positive?
      (1...boundaries.length).each do |to|
        (0...to).reverse_each do |from|
          next if from.zero? && to == final_boundary_index
          break unless add_edge.call(from, to)
        end
      end

      if used_evaluations > budget
        search_completed = false
      end

      states = Array.new(boundaries.length) { Array.new(8) }
      states[0][0] = [0, nil]

      (1...boundaries.length).each do |to|
        final_boundary = to == boundaries.length - 1
        edges[to].each do |edge|
          (0...8).each do |phase|
            predecessor = states[edge.from][phase]
            next unless predecessor

            predecessor_cost = predecessor.first
            [[:fixed, edge.fixed_bits], [:dynamic, edge.dynamic_bits]].each do |block_type, bits|
              next if bits.nil?
              candidate_cost = if final_boundary
                ((predecessor_cost + bits + 7) / 8) * 8
              else
                predecessor_cost + bits
              end
              next_phase = final_boundary ? phase : (phase + bits) % 8
              current = states[to][next_phase]
              if current.nil? || candidate_cost < current.first
                states[to][next_phase] = [
                  candidate_cost,
                  OptimalBackpointer.new(edge.from, phase, block_type)
                ]
              end
            end

            next unless edge.stored_bits
            stored_padding = (8 - phase) & 7
            candidate_cost = if final_boundary
              predecessor_cost + stored_padding + edge.stored_bits
            else
              predecessor_cost + stored_padding + edge.stored_bits
            end
            current = states[to][0]
            if current.nil? || candidate_cost < current.first
              states[to][0] = [
                candidate_cost,
                OptimalBackpointer.new(edge.from, phase, :stored)
              ]
            end
          end
        end
      end

      {
        positions: positions,
        boundaries: boundaries,
        snapshots: snapshots,
        edges: edges,
        states: states,
        used_evaluations: used_evaluations,
        budget: budget,
        exhaustive: exhaustive,
        exhaustive_requested: exhaustive_requested,
        search_completed: search_completed && used_evaluations <= budget &&
          !skipped_dynamic && exhaustive == exhaustive_requested
      }
    end

    def optimal_write_dynamic_header(writer, tree, lit_count, dist_count)
      writer.write(lit_count - 257, 5)
      writer.write(dist_count - 1, 5)
      writer.write(tree.max_blindex + 1 - 4, 4)
      (0..tree.max_blindex).each do |rank|
        symbol = Rbzlib.optimal_bl_order[rank]
        writer.write(tree.bl_tree[symbol].dl, 3)
      end

      optimal_code_length_operations(tree.lit_tree.map(&:dl), lit_count).each do |operation|
        if operation.is_a?(Array)
          symbol, extra, extra_bits = operation
          writer.write(tree.bl_tree[symbol].fc, tree.bl_tree[symbol].dl)
          writer.write(extra, extra_bits)
        else
          writer.write(tree.bl_tree[operation].fc, tree.bl_tree[operation].dl)
        end
      end

      operations = optimal_code_length_operations(tree.dist_tree.map(&:dl), dist_count)
      operations.each do |operation|
        if operation.is_a?(Array)
          symbol, extra, extra_bits = operation
          writer.write(tree.bl_tree[symbol].fc, tree.bl_tree[symbol].dl)
          writer.write(extra, extra_bits)
        else
          writer.write(tree.bl_tree[operation].fc, tree.bl_tree[operation].dl)
        end
      end
    end

    def optimal_write_huffman_token(writer, token, tree)
      type, value, length = token
      if type == :literal
        if tree
          writer.write(tree.lit_tree[value].fc, tree.lit_tree[value].dl)
        else
          static = Rbzlib.optimal_static_trees[0][value]
          writer.write(static.fc, static.dl)
        end
      else
        length_code = optimal_match_length_code(length)
        length_symbol = LITERALS + 1 + length_code
        distance_code = optimal_distance_code(value)
        if tree
          writer.write(tree.lit_tree[length_symbol].fc, tree.lit_tree[length_symbol].dl)
        else
          static = Rbzlib.optimal_static_trees[0][length_symbol]
          writer.write(static.fc, static.dl)
        end
        writer.write(length - MIN_MATCH - Rbzlib.optimal_base_length[length_code],
                     Rbzlib.optimal_extra_lbits[length_code])
        if tree
          writer.write(tree.dist_tree[distance_code].fc, tree.dist_tree[distance_code].dl)
        end
        if tree.nil?
          static = Rbzlib.optimal_static_trees[1][distance_code]
          writer.write(static.fc, static.dl)
        end
        extra = Rbzlib.optimal_extra_dbits[distance_code]
        writer.write(value - 1 - Rbzlib.optimal_base_dist[distance_code], extra)
      end
    end

    def optimal_write_block(writer, input, tokens, positions, snapshots, edge,
                            block_type, last)
      writer.write((last ? 1 : 0) | (block_type == :stored ? 0 :
        (block_type == :fixed ? STATIC_TREES : DYN_TREES) << 1), 3)

      if block_type == :stored
        writer.align
        writer.write(edge.bytes, 16)
        writer.write(edge.bytes ^ 0xffff, 16)
        start = positions[edge.start_token]
        writer.bytes.concat(input.byteslice(start, edge.bytes))
        writer.bit_count += edge.bytes * 8
        if last
          writer.bit_count = (writer.bit_count + 7) & ~7
        end
        return
      end

      tree = nil
      if block_type == :dynamic
        lit = snapshots[edge.to][:lit].map.with_index do |frequency, index|
          frequency - snapshots[edge.from][:lit][index]
        end
        dist = snapshots[edge.to][:dist].map.with_index do |frequency, index|
          frequency - snapshots[edge.from][:dist][index]
        end
        lit[END_BLOCK] += 1
        tree = optimal_dynamic_tree(lit, dist)
        optimal_write_dynamic_header(writer, tree, tree.lit_max + 1, tree.dist_max + 1)
      end

      edge.start_token.upto(edge.end_token - 1) do |index|
        optimal_write_huffman_token(writer, tokens[index], tree)
      end

      if tree
        writer.write(tree.lit_tree[END_BLOCK].fc, tree.lit_tree[END_BLOCK].dl)
      else
        static = Rbzlib.optimal_static_trees[0][END_BLOCK]
        writer.write(static.fc, static.dl)
      end
      if last
        pad = (8 - (writer.bit_count & 7)) & 7
        writer.write(0, pad)
      end
    end

    def optimal_encode(input, tokens, plan)
      boundaries = plan[:boundaries]
      edges = plan[:edges]
      states = plan[:states]
      final_phase = (0...8).min_by { |phase| states.last[phase]&.first || Float::INFINITY }
      backpointer = states.last[final_phase].last
      path = []
      boundary_index = boundaries.length - 1
      phase = final_phase

      while boundary_index.positive?
        edge = edges[boundary_index].find { |candidate| candidate.from == backpointer.boundary }
        path.unshift([edge, backpointer.block_type, boundary_index == boundaries.length - 1])
        boundary_index = backpointer.boundary
        phase = backpointer.phase
        backpointer = states[boundary_index][phase].last
      end

      writer = OptimalBitWriter.new
      path.each do |edge, block_type, last|
        optimal_write_block(
          writer, input, tokens, plan[:positions], plan[:snapshots],
          edge, block_type, last
        )
      end
      writer.finish
    end

    def optimal_selected_path(plan)
      boundaries = plan[:boundaries]
      edges = plan[:edges]
      states = plan[:states]
      final_phase = (0...8).min_by { |phase| states.last[phase]&.first || Float::INFINITY }
      backpointer = states.last[final_phase].last
      path = []
      boundary_index = boundaries.length - 1
      phase = final_phase

      while boundary_index.positive?
        edge = edges[boundary_index].find { |candidate| candidate.from == backpointer.boundary }
        path.unshift([edge, backpointer.block_type])
        boundary_index = backpointer.boundary
        phase = backpointer.phase
        backpointer = states[boundary_index][phase].last
      end

      path
    end

    def optimal_diagnostic(input, output, parsed, plan, budget, window_bits)
      path = optimal_selected_path(plan)
      block_counts = Hash.new(0)
      cross_window_references = 0
      positions = plan[:positions]

      path.each do |edge, _block_type|
        edge.start_token.upto(edge.end_token - 1) do |token_index|
          token = parsed[:tokens][token_index]
          next unless token[0] == :match

          block_start = positions[edge.start_token]
          token_start = positions[token_index]
          cross_window_references += 1 if token[1] > token_start - block_start
        end
      end

      path.each { |_edge, block_type| block_counts[block_type] += 1 }
      selected_search = plan[:exhaustive] ? 'exhaustive' : 'bounded'
      {
        mode: 'optimal',
        level: parsed[:level] || 9,
        window_bits: window_bits,
        input_bytes: input.bytesize,
        output_bytes: output.bytesize,
        output_bits: output.bytesize * 8,
        blocks: path.length,
        block_types: block_counts,
        cross_block_references: cross_window_references,
        tokens: parsed[:tokens].length,
        matches: parsed[:tokens].count { |token| token[0] == :match },
        match_evaluations: parsed[:match_evaluations],
        candidate_boundaries: plan[:boundaries].length,
        dynamic_tree_evaluations: plan[:used_evaluations],
        budget: budget,
        selected_search: selected_search,
        exhaustive_requested: plan[:exhaustive_requested],
        search_completed: plan[:search_completed]
      }
    end
  end
end

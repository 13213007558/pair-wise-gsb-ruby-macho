# frozen_string_literal: true

module MachO
  module ObjC2
    # Bounded, diagnostic-collecting reader over a fixed file image.
    #
    # All reads go through the caller-provided mapper; unmapped or truncated
    # reads return nil and record a diagnostic instead of raising, so a
    # single corrupt pointer never aborts the whole extraction.
    class Reader
      # @return [Array<Hash>] diagnostics collected so far, each a
      #   serializable hash with "level", "address" and "message" keys
      attr_reader :diagnostics

      # @param data [String] the raw file bytes
      # @param mapper [#call] maps a vmaddr to a file offset or nil
      def initialize(data, mapper)
        @data = data
        @mapper = mapper
        @diagnostics = []
        @seen_diagnostics = {}
      end

      # Reads an unsigned 64-bit little-endian integer.
      # @param address [Integer] the vmaddr to read from
      # @param context [String, nil] description used in diagnostics
      # @return [Integer, nil] the value, or nil if unreadable
      def u64(address, context: nil)
        unpack(address, 8, "Q<", context)
      end

      # Reads an unsigned 32-bit little-endian integer.
      # @param address [Integer] the vmaddr to read from
      # @param context [String, nil] description used in diagnostics
      # @return [Integer, nil] the value, or nil if unreadable
      def u32(address, context: nil)
        unpack(address, 4, "L<", context)
      end

      # Reads a signed 32-bit little-endian integer.
      # @param address [Integer] the vmaddr to read from
      # @param context [String, nil] description used in diagnostics
      # @return [Integer, nil] the value, or nil if unreadable
      def i32(address, context: nil)
        unpack(address, 4, "l<", context)
      end

      # Reads a NUL-terminated string.
      # @param address [Integer] the vmaddr to read from
      # @param context [String, nil] description used in diagnostics
      # @return [String, nil] the string, or nil if unreadable
      def cstring(address, context: nil)
        offset = offset_for(address, context)
        return if offset.nil?

        limit = [offset + MAX_CSTRING_LENGTH, @data.bytesize].min
        cursor = offset
        cursor += 1 while cursor < limit && @data.getbyte(cursor) != 0
        if cursor == limit
          diagnose(address, "unterminated string", context)
          return
        end

        @data[offset...cursor].force_encoding(Encoding::UTF_8).scrub
      end

      # Records a diagnostic, deduplicating identical entries.
      # @param address [Integer] the offending vmaddr
      # @param message [String] what went wrong
      # @param context [String, nil] where it happened
      # @return [void]
      def diagnose(address, message, context = nil)
        message = "#{message} (#{context})" if context
        key = [address, message]
        return if @seen_diagnostics.key?(key)

        @seen_diagnostics[key] = true
        @diagnostics << {
          "level" => "warning",
          "address" => address,
          "message" => message,
        }
      end

      private

      def unpack(address, size, directive, context)
        offset = offset_for(address, context)
        return if offset.nil?

        if offset + size > @data.bytesize
          diagnose(address, "truncated #{size * 8}-bit read", context)
          return
        end

        @data.unpack1(directive, :offset => offset)
      end

      def offset_for(address, context)
        offset = @mapper.call(address)
        if offset.nil? || offset.negative?
          diagnose(address, "unmapped pointer 0x#{address.to_s(16)}", context)
          return
        end

        offset
      end
    end
  end
end



module Hana
  VERSION = '1.2.1'
end

module Hana
  # This module contains the code to convert between an JSON pointer path
  # representation and the keys required to traverse an array. It can make use
  # of an a path and evaluate it against a provided (potentially deeply nested)
  # array or hash.
  #
  # This is mostly compliant with RFC6901, however, a few small exceptions have
  # been made, though they shouldn't break compatibility with pure
  # implementations.
  module Pointer
    # Given a parsed path and an object, get the nested value within the object.
    #
    # @param [Array<String,Fixnum>] path Key path to traverse to get the value.
    # @param [Hash,Array] obj The document to traverse.
    # @return [Object] The value at the provided path.
    def eval(path, obj)
      path.inject(obj) do |o, p|
        if o.is_a?(Hash)
          raise MissingTargetException unless o.keys.include?(p)
          o[p]
        elsif o.is_a?(Array)
          # The last element +1 is technically how this is interpretted. This
          # will always trigger the index error so it may not be valuable to
          # set...
          p = o.size if p == "-1"
          # Technically a violation of the RFC to allow reverse access to the
          # array but I'll allow it...
          raise ObjectOperationOnArrayException unless p.to_s.match(/\A-?\d+\Z/)
          raise IndexError unless p.to_i.abs < o.size
          o[p.to_i]
        else
          # We received a Scalar value from the prior iteration... we can't do
          # anything with this...
          raise MissingTargetException
        end
      end
    end

    # Given an array of keys this will provide a properly escaped JSONPointer
    # path.
    #
    # @param [Array<String,Fixnum>] ary_path
    # @return [String]
    def encode(ary_path)
      ary_path = Array(ary_path).map { |p| p.is_a?(String) ? escape(p) : p }
      "/" << ary_path.join("/")
    end

    # Escapes reserved characters as defined by RFC6901. This is intended to
    # escape individual segments of the pointer and thus should not be run on an
    # already generated path.
    #
    # @see [Pointer#unescape]
    # @param [String] str
    # @return [String]
    def escape(str)
      conv = { '~' => '~0', '/' => '~1' }
      str.gsub(/~|\//) { |m| conv[m] }
    end

    # Convert a JSON pointer into an array of keys that can be used to traverse
    # a parsed JSON document.
    #
    # @param [String] path
    # @return [Array<String,Fixnum>]
    def parse(path)
      # I'm pretty sure this isn't quite valid but it's a holdover from
      # tenderlove's code. Once the operations are refactored I believe this
      # won't be necessary.
      return [""] if path == "/"
      # Strip off the leading slash
      path = path.sub(/^\//, '')
      path.split("/").map { |p| unescape(p) }
    end

    # Unescapes any reserved characters within a JSON pointer segment.
    #
    # @see [Pointer#escape]
    # @param [String]
    # @return [String]
    def unescape(str)
      conv = { '~0' => '~', '~1' => '/' }
      str.gsub(/~[01]/) { |m| conv[m] }
    end

    module_function :eval, :encode, :escape, :parse, :unescape
  end
end

module Hana
  Exception = Class.new(StandardError)

  OutOfBoundsException = Class.new(Hana::Exception)
  ObjectOperationOnArrayException = Class.new(Hana::Exception)
  IndexError = Class.new(Hana::Exception)
  MissingTargetException = Class.new(Hana::Exception)

  class FailedTestException < Hana::Exception
    attr_accessor :path, :value

    def initialize(path, value)
      super("Expected #{value} at #{path}")
    end
  end
end

module Hana
  class Patch
    VALID_OPERATIONS = %w{ add move test replace remove copy } # :nodoc:

    def initialize(patch_operations)
      @patch_operations = patch_operations
    end

    def apply(doc)
      @patch_operations.each_with_object(doc) do |patch, cur_doc|
        unless VALID_OPERATIONS.include?(patch['op'])
          raise Hana::Exception, "bad method `#{patch['op']}`" 
        end

        send(patch['op'], patch, cur_doc)
      end
    end

    private

    PATH  = 'path' # :nodoc:
    FROM  = 'from' # :nodoc:
    VALUE = 'value' # :nodoc:
    OP    = 'op' # :nodoc:

    def add(patch_info, doc)
      path = Pointer.parse(patch_info['path'])
      key  = path.pop
      dest_obj = Pointer.eval(path, doc)
      new_value  = patch_info['value']

      raise(MissingTargetException, patch_info['path']) unless dest_obj

      if key
        add_op(dest_obj, key, new_value)
      else
        dest_obj.replace(new_value)
      end
    end

    def move ins, doc
      from     = Pointer.parse ins[FROM]
      to       = Pointer.parse ins[PATH]
      from_key = from.pop
      key      = to.pop
      src      = Pointer.eval from, doc
      dest     = Pointer.eval to, doc

      obj = rm_op src, from_key
      add_op dest, key, obj
    end

    def copy ins, doc
      from     = Pointer.parse ins[FROM]
      to       = Pointer.parse ins[PATH]
      from_key = from.pop
      key      = to.pop
      src      = Pointer.eval from, doc
      dest     = Pointer.eval to, doc

      if Array === src
        raise IndexError unless from_key =~ /\A\d+\Z/
        obj = src.fetch from_key.to_i
      else
        obj = src.fetch from_key
      end

      add_op dest, key, obj
    end

    def test ins, doc
      expected = Pointer.eval(Pointer.parse(ins[PATH]), doc)

      unless expected == ins[VALUE]
        raise FailedTestException.new(ins[VALUE], ins[PATH])
      end
    end

    def replace(ins, doc)
      list = Pointer.parse(ins[PATH])
      key  = list.pop
      obj  = Pointer.eval(list, doc)

      if Array === obj
        raise IndexError unless key =~ /\A\d+\Z/
        obj[key.to_i] = ins[VALUE]
      else
        obj[key] = ins[VALUE]
      end
    end

    def remove ins, doc
      list = Pointer.parse ins[PATH]
      key  = list.pop
      obj  = Pointer.eval list, doc
      rm_op obj, key
    end

    def check_index obj, key
      return -1 if key == '-'

      raise ObjectOperationOnArrayException unless key =~ /\A-?\d+\Z/
      idx = key.to_i
      raise OutOfBoundsException if idx > obj.length || idx < 0
      idx
    end

    def add_op dest, key, obj
      if Array === dest
        dest.insert check_index(dest, key), obj
      else
        dest[key] = obj
      end
    end

    def rm_op obj, key
      if Array === obj
        raise IndexError unless key =~ /\A\d+\Z/
        obj.delete_at key.to_i
      else
        obj.delete key
      end
    end
  end
end

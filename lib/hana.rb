
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

  OutOfBoundsException            = Class.new(Hana::Exception)
  ObjectOperationOnArrayException = Class.new(Hana::Exception)
  IndexError                      = Class.new(Hana::Exception)
  MissingTargetException          = Class.new(Hana::Exception)
  InvalidOperation                = Class.new(Hana::Exception)

  class FailedTestException < Hana::Exception
    attr_accessor :path, :value

    def initialize(path, value)
      super("Expected #{value} at #{path}")
    end
  end
end

class Hana::Patch
  def initialize(patch_operations)
    @patch_operations = patch_operations
  end

  def apply(doc)
    @patch_operations.each_with_object(doc) do |patch, cur_doc|
      op_const = patch['op'].capitalize.to_sym

      unless Hana::Operations.const_defined?(op_const)
        raise Hana::InvalidOperation, "Invalid operation: `#{patch['op']}`" 
      end

      Hana::Operations.const_get(op_const).apply(patch, cur_doc)
    end
  end
end

module Hana::Operations
  # Add an item with
  def add_op(dest_obj, key, new_value)
    if dest_obj.is_a?(Array)
      if key == '-'
        dest_obj.insert(-1, new_value)
      else
        raise Hana::ObjectOperationOnArrayException unless key =~ /\A-?\d+\Z/
        key = key.to_i
        raise Hana::OutOfBoundsException if (key > dest_obj.size || key < 0)
        dest_obj.insert(key, new_value)
      end
    else
      dest_obj[key] = new_value
    end
  end

  def rm_op(obj, key)
    if obj.is_a?(Array)
      raise Hana::IndexError unless key =~ /\A\d+\Z/
      obj.delete_at(key.to_i)
    else
      obj.delete(key)
    end
  end

  module_function :add_op, :rm_op
end

module Hana::Operations::Add
  def apply(patch_info, doc)
    path      = Hana::Pointer.parse(patch_info['path'])
    key       = path.pop
    dest_obj  = Hana::Pointer.eval(path, doc)
    new_value = patch_info['value']

    raise(MissingTargetException, patch_info['path']) unless dest_obj

    if key
      Hana::Operations.add_op(dest_obj, key, new_value)
    else
      dest_obj.replace(new_value)
    end
  end

  module_function :apply
end

module Hana::Operations::Move
  def apply(ins, doc)
    from     = Hana::Pointer.parse(ins['from'])
    to       = Hana::Pointer.parse(ins['path'])
    from_key = from.pop
    key      = to.pop
    src      = Hana::Pointer.eval(from, doc)
    dest     = Hana::Pointer.eval(to, doc)

    obj = Hana::Operations.rm_op(src, from_key)
    Hana::Operations.add_op(dest, key, obj)
  end

  module_function :apply
end

module Hana::Operations::Copy
  def apply(ins, doc)
    from     = Hana::Pointer.parse(ins['from'])
    to       = Hana::Pointer.parse(ins['path'])
    from_key = from.pop
    key      = to.pop
    src      = Hana::Pointer.eval(from, doc)
    dest     = Hana::Pointer.eval(to, doc)

    if src.is_a?(Array)
      raise Hana::IndexError unless from_key =~ /\A\d+\Z/
      obj = src.fetch(from_key.to_i)
    else
      obj = src.fetch(from_key)
    end

    Hana::Operations.add_op(dest, key, obj)
  end

  module_function :apply
end

module Hana
  module Operations
    module Test
      def apply(ins, doc)
        expected = Pointer.eval(Pointer.parse(ins['path']), doc)

        unless expected == ins['value']
          raise FailedTestException.new(ins['value'], ins['path'])
        end
      end

      module_function :apply
    end
  end
end

module Hana
  module Operations
    module Replace
      def apply(ins, doc)
        list = Pointer.parse(ins['path'])
        key  = list.pop
        obj  = Pointer.eval(list, doc)

        if Array === obj
          raise IndexError unless key =~ /\A\d+\Z/
          obj[key.to_i] = ins['value']
        else
          obj[key] = ins['value']
        end
      end

      module_function :apply
    end
  end
end

module Hana
  module Operations
    module Remove
      def apply(ins, doc)
        list = Pointer.parse(ins['path'])
        key  = list.pop
        obj  = Pointer.eval(list, doc)
        Operations.rm_op(obj, key)
      end

      module_function :apply
    end
  end
end


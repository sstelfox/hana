
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

# These operations take advantage of the fact that Pointer#eval returns the same
# object (obj.object_id match) and thus any changes made to the extracted object
# will be reflected in the original deeply nested object.
module Hana::Operations

  # Add a value at the provided key within the provided object. This will behave
  # differently depending on whether we're processing a hash or an array as the
  # target destination.
  def add_op(dest_obj, key, new_value)
    if dest_obj.is_a?(Array)
      dest_obj.insert(check_array_index(key, dest_obj.size), new_value)
    else
      dest_obj[key] = new_value
    end
  end

  def check_array_index(index, array_size)
    return -1 if index == "-"
    raise Hana::ObjectOperationOnArrayException unless index =~ /\A-?\d+\Z/
    index = index.to_i
    # There is a bug in the IETF tests that require us to allow patches to set a
    # value at the end of the array. The final '<=' should actually be a '<'.
    raise Hana::OutOfBoundsException unless (0 <= index && index <= array_size)
    index
  end

  def rm_op(obj, key)
    if obj.is_a?(Array)
      raise Hana::IndexError unless key =~ /\A\d+\Z/
      obj.delete_at(key.to_i)
    else
      obj.delete(key)
    end
  end

  module_function :add_op, :check_array_index, :rm_op
end

module Hana::Operations::Add
  def apply(patch_info, target_doc)
    path      = Hana::Pointer.parse(patch_info['path'])
    key       = path.pop
    dest_obj  = Hana::Pointer.eval(path, target_doc)
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
  def apply(patch_data, target_doc)
    from     = Hana::Pointer.parse(patch_data['from'])
    to       = Hana::Pointer.parse(patch_data['path'])
    from_key = from.pop
    key      = to.pop
    src      = Hana::Pointer.eval(from, target_doc)
    dest     = Hana::Pointer.eval(to, target_doc)

    obj = Hana::Operations.rm_op(src, from_key)
    Hana::Operations.add_op(dest, key, obj)
  end

  module_function :apply
end

module Hana::Operations::Copy
  def apply(patch_data, target_doc)
    from     = Hana::Pointer.parse(patch_data['from'])
    to       = Hana::Pointer.parse(patch_data['path'])
    from_key = from.pop
    key      = to.pop
    src      = Hana::Pointer.eval(from, target_doc)
    dest     = Hana::Pointer.eval(to, target_doc)

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

module Hana::Operations::Test
  # A simple test to validate the value at the expected location matches the
  # value in the patch information.
  def apply(patch_data, target_doc)
    expected = Hana::Pointer.eval(Hana::Pointer.parse(patch_data['path']), target_doc)

    unless expected == patch_data['value']
      raise Hana::FailedTestException.new(patch_data['value'], patch_data['path'])
    end
  end

  module_function :apply
end

module Hana::Operations::Replace
  def apply(patch_data, target_doc)
    list = Hana::Pointer.parse(patch_data['path'])
    key  = list.pop
    obj  = Hana::Pointer.eval(list, target_doc)

    if obj.is_a?(Array)
      raise Hana::IndexError unless key =~ /\A\d+\Z/
      obj[key.to_i] = patch_data['value']
    else
      obj[key] = patch_data['value']
    end
  end

  module_function :apply
end

module Hana::Operations::Remove
  def apply(patch_data, target_doc)
    list = Hana::Pointer.parse(patch_data['path'])
    key  = list.pop
    obj  = Hana::Pointer.eval(list, target_doc)

    Hana::Operations.rm_op(obj, key)
  end

  module_function :apply
end


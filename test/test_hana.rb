require 'helper'

class TestHana < Hana::TestCase
  def test_no_eval
    patch = Hana::Patch.new [
      { 'op' => 'eval', 'value' => '1' }
    ]
    assert_raises(Hana::Exception) do
      patch.apply('foo' => 'bar')
    end
  end

  def test_split_many
    pointer = Hana::Pointer.parse('/foo/bar/baz')
    assert_equal %w{ foo bar baz }, pointer.to_a
  end

  def test_root
    pointer = Hana::Pointer.parse('/')
    assert_equal [''], pointer.to_a
  end

  def test_eval_hash
    pointer = Hana::Pointer.parse('/foo')
    assert_equal 'bar', Hana::Pointer.eval(pointer, 'foo' => 'bar')

    pointer = Hana::Pointer.parse('/foo/bar')
    assert_equal 'baz', Hana::Pointer.eval(pointer, 'foo' => { 'bar' => 'baz' })
  end

  def test_deep_nest
    pointer = Hana::Pointer.parse('/deep/nest/hash')
    sample_doc = {'deep' => {'nest' => {'hash' => 3}}}
    assert_equal 3, Hana::Pointer.eval(pointer, sample_doc)
  end

  def test_eval_array
    pointer = Hana::Pointer.parse('/foo/1')
    assert_equal 'baz', Hana::Pointer.eval(pointer, 'foo' => ['bar', 'baz'])

    pointer = Hana::Pointer.parse('/foo/0/bar')
    assert_equal 'omg', Hana::Pointer.eval(pointer, 'foo' => [{'bar' => 'omg'}, 'baz'])
  end

  def test_eval_number_as_key
    pointer = Hana::Pointer.parse('/foo/1')
    assert_equal 'baz', Hana::Pointer.eval(pointer, 'foo' => { '1' => 'baz' })
  end
end

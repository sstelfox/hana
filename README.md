# hana

* http://github.com/tenderlove/hana

## DESCRIPTION:

Implementation of [JSON Patch][1] and [JSON Pointer][2] drafts.

## FEATURES/PROBLEMS:

Implements draft specs of the [JSON Patch][1] and [JSON pointer][2] spec:


These are drafts, so it could change.  This works against Ruby objects, so you
should load the JSON to Ruby, process it, then emit as JSON again.

## SYNOPSIS:

```ruby
patch = Hana::Patch.new [
  { 'add' => '/baz', 'value' => 'qux' }
]

patch.apply('foo' => 'bar') # => {'baz' => 'qux', 'foo' => 'bar'}
```

## REQUIREMENTS:

* Ruby

## INSTALL:

    $ gem install hana

## LICENSE:

(The MIT License)

Copyright (c) 2012 Aaron Patterson

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
'Software'), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

[1]: http://tools.ietf.org/html/draft-ietf-appsawg-json-patch-03
[2]: http://tools.ietf.org/html/draft-ietf-appsawg-json-pointer-01
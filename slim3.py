import collections.abc

#hyper needs the four following aliases to be done manually.
collections.Iterable = collections.abc.Iterable
collections.Iterator = collections.abc.Iterator
collections.Mapping = collections.abc.Mapping
collections.MutableSet = collections.abc.MutableSet
collections.MutableMapping = collections.abc.MutableMapping
collections.ItemsView = collections.abc.ItemsView
collections.KeysView = collections.abc.KeysView
collections.ValuesView = collections.abc.ValuesView
collections.Set = collections.abc.Set
collections.MutableSequence = collections.abc.MutableSequence

import re
import sys
from slim.__main__ import main

if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
    sys.exit(main())

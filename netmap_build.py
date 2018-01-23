import os
from cffi import FFI


def read_file(name):
    with open(name) as f:
        return f.read()


CDIR = 'src'
HEADERS = os.path.join(CDIR, 'pynetmap.h')
SRC = os.path.join(CDIR, 'pynetmap.c')

ffibuilder = FFI()
ffibuilder.cdef(read_file(HEADERS))
ffibuilder.set_source("_pynetmap", read_file(SRC), include_dirs=['include'], define_macros=[
    ('NETMAP_WITH_LIBS', '1')
])


if __name__ == "__main__":
    ffibuilder.compile(verbose=True, debug=True)
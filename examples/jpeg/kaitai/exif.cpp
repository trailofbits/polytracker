// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "exif.h"


#include "exif_be.h"
#include "exif_le.h"

exif_t::exif_t(kaitai::kstream* p__io, kaitai::kstruct* p__parent, exif_t* p__root) : kaitai::kstruct(p__io) {
    m__parent = p__parent;
    m__root = this;
    _read();
}

void exif_t::_read() {
    m_endianness = m__io->read_u2le();
    n_body = true;
    switch (endianness()) {
    case 18761: {
        n_body = false;
        m_body = new exif_le_t(m__io);
        break;
    }
    case 19789: {
        n_body = false;
        m_body = new exif_be_t(m__io);
        break;
    }
    }
}

exif_t::~exif_t() {
    if (!n_body) {
        delete m_body;
    }
}

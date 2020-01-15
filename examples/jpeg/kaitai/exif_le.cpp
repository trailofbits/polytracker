// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "exif_le.h"



exif_le_t::exif_le_t(kaitai::kstream* p__io, kaitai::kstruct* p__parent, exif_le_t* p__root) : kaitai::kstruct(p__io) {
    m__parent = p__parent;
    m__root = this;
    f_ifd0 = false;
    _read();
}

void exif_le_t::_read() {
    m_version = m__io->read_u2le();
    m_ifd0_ofs = m__io->read_u4le();
}

exif_le_t::~exif_le_t() {
    if (f_ifd0) {
        delete m_ifd0;
    }
}

exif_le_t::ifd_t::ifd_t(kaitai::kstream* p__io, kaitai::kstruct* p__parent, exif_le_t* p__root) : kaitai::kstruct(p__io) {
    m__parent = p__parent;
    m__root = p__root;
    f_next_ifd = false;
    _read();
}

void exif_le_t::ifd_t::_read() {
    m_num_fields = m__io->read_u2le();
    int l_fields = num_fields();
    m_fields = new std::vector<ifd_field_t*>();
    m_fields->reserve(l_fields);
    for (int i = 0; i < l_fields; i++) {
        m_fields->push_back(new ifd_field_t(m__io, this, m__root));
    }
    m_next_ifd_ofs = m__io->read_u4le();
}

exif_le_t::ifd_t::~ifd_t() {
    for (std::vector<ifd_field_t*>::iterator it = m_fields->begin(); it != m_fields->end(); ++it) {
        delete *it;
    }
    delete m_fields;
    if (f_next_ifd && !n_next_ifd) {
        delete m_next_ifd;
    }
}

exif_le_t::ifd_t* exif_le_t::ifd_t::next_ifd() {
    if (f_next_ifd)
        return m_next_ifd;
    n_next_ifd = true;
    if (next_ifd_ofs() != 0) {
        n_next_ifd = false;
        std::streampos _pos = m__io->pos();
        m__io->seek(next_ifd_ofs());
        m_next_ifd = new ifd_t(m__io, this, m__root);
        m__io->seek(_pos);
    }
    f_next_ifd = true;
    return m_next_ifd;
}

exif_le_t::ifd_field_t::ifd_field_t(kaitai::kstream* p__io, exif_le_t::ifd_t* p__parent, exif_le_t* p__root) : kaitai::kstruct(p__io) {
    m__parent = p__parent;
    m__root = p__root;
    f_type_byte_length = false;
    f_byte_length = false;
    f_is_immediate_data = false;
    f_data = false;
    _read();
}

void exif_le_t::ifd_field_t::_read() {
    m_tag = static_cast<exif_le_t::ifd_field_t::tag_enum_t>(m__io->read_u2le());
    m_field_type = static_cast<exif_le_t::ifd_field_t::field_type_enum_t>(m__io->read_u2le());
    m_length = m__io->read_u4le();
    m_ofs_or_data = m__io->read_u4le();
}

exif_le_t::ifd_field_t::~ifd_field_t() {
    if (f_data && !n_data) {
    }
}

int8_t exif_le_t::ifd_field_t::type_byte_length() {
    if (f_type_byte_length)
        return m_type_byte_length;
    m_type_byte_length = ((field_type() == FIELD_TYPE_ENUM_WORD) ? (2) : (((field_type() == FIELD_TYPE_ENUM_DWORD) ? (4) : (1))));
    f_type_byte_length = true;
    return m_type_byte_length;
}

int32_t exif_le_t::ifd_field_t::byte_length() {
    if (f_byte_length)
        return m_byte_length;
    m_byte_length = (length() * type_byte_length());
    f_byte_length = true;
    return m_byte_length;
}

bool exif_le_t::ifd_field_t::is_immediate_data() {
    if (f_is_immediate_data)
        return m_is_immediate_data;
    m_is_immediate_data = byte_length() <= 4;
    f_is_immediate_data = true;
    return m_is_immediate_data;
}

std::string exif_le_t::ifd_field_t::data() {
    if (f_data)
        return m_data;
    n_data = true;
    if (!(is_immediate_data())) {
        n_data = false;
        kaitai::kstream *io = _root()->_io();
        std::streampos _pos = io->pos();
        io->seek(ofs_or_data());
        m_data = io->read_bytes(byte_length());
        io->seek(_pos);
    }
    f_data = true;
    return m_data;
}

exif_le_t::ifd_t* exif_le_t::ifd0() {
    if (f_ifd0)
        return m_ifd0;
    std::streampos _pos = m__io->pos();
    m__io->seek(ifd0_ofs());
    m_ifd0 = new ifd_t(m__io, this, m__root);
    m__io->seek(_pos);
    f_ifd0 = true;
    return m_ifd0;
}

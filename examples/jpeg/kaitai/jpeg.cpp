// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "jpeg.h"


#include "exif.h"

jpeg_t::jpeg_t(kaitai::kstream* p__io, kaitai::kstruct* p__parent, jpeg_t* p__root) : kaitai::kstruct(p__io) {
    m__parent = p__parent;
    m__root = this;
    _read();
}

void jpeg_t::_read() {
    m_segments = new std::vector<segment_t*>();
    {
        int i = 0;
        while (!m__io->is_eof()) {
            m_segments->push_back(new segment_t(m__io, this, m__root));
            i++;
        }
    }
}

jpeg_t::~jpeg_t() {
    for (std::vector<segment_t*>::iterator it = m_segments->begin(); it != m_segments->end(); ++it) {
        delete *it;
    }
    delete m_segments;
}

jpeg_t::segment_t::segment_t(kaitai::kstream* p__io, jpeg_t* p__parent, jpeg_t* p__root) : kaitai::kstruct(p__io) {
    m__parent = p__parent;
    m__root = p__root;
    _read();
}

void jpeg_t::segment_t::_read() {
    m_magic = m__io->ensure_fixed_contents(std::string("\xFF", 1));
    m_marker = static_cast<jpeg_t::segment_t::marker_enum_t>(m__io->read_u1());
    n_length = true;
    if ( ((marker() != MARKER_ENUM_SOI) && (marker() != MARKER_ENUM_EOI)) ) {
        n_length = false;
        m_length = m__io->read_u2be();
    }
    n_data = true;
    if ( ((marker() != MARKER_ENUM_SOI) && (marker() != MARKER_ENUM_EOI)) ) {
        n_data = false;
        n_data = true;
        switch (marker()) {
        case MARKER_ENUM_SOS: {
            n_data = false;
            m__raw_data = m__io->read_bytes((length() - 2));
            m__io__raw_data = new kaitai::kstream(m__raw_data);
            m_data = new segment_sos_t(m__io__raw_data, this, m__root);
            break;
        }
        case MARKER_ENUM_APP1: {
            n_data = false;
            m__raw_data = m__io->read_bytes((length() - 2));
            m__io__raw_data = new kaitai::kstream(m__raw_data);
            m_data = new segment_app1_t(m__io__raw_data, this, m__root);
            break;
        }
        case MARKER_ENUM_SOF0: {
            n_data = false;
            m__raw_data = m__io->read_bytes((length() - 2));
            m__io__raw_data = new kaitai::kstream(m__raw_data);
            m_data = new segment_sof0_t(m__io__raw_data, this, m__root);
            break;
        }
        case MARKER_ENUM_APP0: {
            n_data = false;
            m__raw_data = m__io->read_bytes((length() - 2));
            m__io__raw_data = new kaitai::kstream(m__raw_data);
            m_data = new segment_app0_t(m__io__raw_data, this, m__root);
            break;
        }
        default: {
            m__raw_data = m__io->read_bytes((length() - 2));
            break;
        }
        }
    }
    n_image_data = true;
    if (marker() == MARKER_ENUM_SOS) {
        n_image_data = false;
        m_image_data = m__io->read_bytes_full();
    }
}

jpeg_t::segment_t::~segment_t() {
    if (!n_length) {
    }
    if (!n_data) {
        delete m__io__raw_data;
        delete m_data;
    }
    if (!n_image_data) {
    }
}

jpeg_t::segment_sos_t::segment_sos_t(kaitai::kstream* p__io, jpeg_t::segment_t* p__parent, jpeg_t* p__root) : kaitai::kstruct(p__io) {
    m__parent = p__parent;
    m__root = p__root;
    _read();
}

void jpeg_t::segment_sos_t::_read() {
    m_num_components = m__io->read_u1();
    int l_components = num_components();
    m_components = new std::vector<component_t*>();
    m_components->reserve(l_components);
    for (int i = 0; i < l_components; i++) {
        m_components->push_back(new component_t(m__io, this, m__root));
    }
    m_start_spectral_selection = m__io->read_u1();
    m_end_spectral = m__io->read_u1();
    m_appr_bit_pos = m__io->read_u1();
}

jpeg_t::segment_sos_t::~segment_sos_t() {
    for (std::vector<component_t*>::iterator it = m_components->begin(); it != m_components->end(); ++it) {
        delete *it;
    }
    delete m_components;
}

jpeg_t::segment_sos_t::component_t::component_t(kaitai::kstream* p__io, jpeg_t::segment_sos_t* p__parent, jpeg_t* p__root) : kaitai::kstruct(p__io) {
    m__parent = p__parent;
    m__root = p__root;
    _read();
}

void jpeg_t::segment_sos_t::component_t::_read() {
    m_id = static_cast<jpeg_t::component_id_t>(m__io->read_u1());
    m_huffman_table = m__io->read_u1();
}

jpeg_t::segment_sos_t::component_t::~component_t() {
}

jpeg_t::segment_app1_t::segment_app1_t(kaitai::kstream* p__io, jpeg_t::segment_t* p__parent, jpeg_t* p__root) : kaitai::kstruct(p__io) {
    m__parent = p__parent;
    m__root = p__root;
    _read();
}

void jpeg_t::segment_app1_t::_read() {
    m_magic = kaitai::kstream::bytes_to_str(m__io->read_bytes_term(0, false, true, true), std::string("ASCII"));
    n_body = true;
    {
        std::string on = magic();
        if (on == std::string("Exif")) {
            n_body = false;
            m_body = new exif_in_jpeg_t(m__io, this, m__root);
        }
    }
}

jpeg_t::segment_app1_t::~segment_app1_t() {
    if (!n_body) {
        delete m_body;
    }
}

jpeg_t::segment_sof0_t::segment_sof0_t(kaitai::kstream* p__io, jpeg_t::segment_t* p__parent, jpeg_t* p__root) : kaitai::kstruct(p__io) {
    m__parent = p__parent;
    m__root = p__root;
    _read();
}

void jpeg_t::segment_sof0_t::_read() {
    m_bits_per_sample = m__io->read_u1();
    m_image_height = m__io->read_u2be();
    m_image_width = m__io->read_u2be();
    m_num_components = m__io->read_u1();
    int l_components = num_components();
    m_components = new std::vector<component_t*>();
    m_components->reserve(l_components);
    for (int i = 0; i < l_components; i++) {
        m_components->push_back(new component_t(m__io, this, m__root));
    }
}

jpeg_t::segment_sof0_t::~segment_sof0_t() {
    for (std::vector<component_t*>::iterator it = m_components->begin(); it != m_components->end(); ++it) {
        delete *it;
    }
    delete m_components;
}

jpeg_t::segment_sof0_t::component_t::component_t(kaitai::kstream* p__io, jpeg_t::segment_sof0_t* p__parent, jpeg_t* p__root) : kaitai::kstruct(p__io) {
    m__parent = p__parent;
    m__root = p__root;
    f_sampling_x = false;
    f_sampling_y = false;
    _read();
}

void jpeg_t::segment_sof0_t::component_t::_read() {
    m_id = static_cast<jpeg_t::component_id_t>(m__io->read_u1());
    m_sampling_factors = m__io->read_u1();
    m_quantization_table_id = m__io->read_u1();
}

jpeg_t::segment_sof0_t::component_t::~component_t() {
}

int32_t jpeg_t::segment_sof0_t::component_t::sampling_x() {
    if (f_sampling_x)
        return m_sampling_x;
    m_sampling_x = ((sampling_factors() & 240) >> 4);
    f_sampling_x = true;
    return m_sampling_x;
}

int32_t jpeg_t::segment_sof0_t::component_t::sampling_y() {
    if (f_sampling_y)
        return m_sampling_y;
    m_sampling_y = (sampling_factors() & 15);
    f_sampling_y = true;
    return m_sampling_y;
}

jpeg_t::exif_in_jpeg_t::exif_in_jpeg_t(kaitai::kstream* p__io, jpeg_t::segment_app1_t* p__parent, jpeg_t* p__root) : kaitai::kstruct(p__io) {
    m__parent = p__parent;
    m__root = p__root;
    _read();
}

void jpeg_t::exif_in_jpeg_t::_read() {
    m_extra_zero = m__io->ensure_fixed_contents(std::string("\x00", 1));
    m__raw_data = m__io->read_bytes_full();
    m__io__raw_data = new kaitai::kstream(m__raw_data);
    m_data = new exif_t(m__io__raw_data);
}

jpeg_t::exif_in_jpeg_t::~exif_in_jpeg_t() {
    delete m__io__raw_data;
    delete m_data;
}

jpeg_t::segment_app0_t::segment_app0_t(kaitai::kstream* p__io, jpeg_t::segment_t* p__parent, jpeg_t* p__root) : kaitai::kstruct(p__io) {
    m__parent = p__parent;
    m__root = p__root;
    _read();
}

void jpeg_t::segment_app0_t::_read() {
    m_magic = kaitai::kstream::bytes_to_str(m__io->read_bytes(5), std::string("ASCII"));
    m_version_major = m__io->read_u1();
    m_version_minor = m__io->read_u1();
    m_density_units = static_cast<jpeg_t::segment_app0_t::density_unit_t>(m__io->read_u1());
    m_density_x = m__io->read_u2be();
    m_density_y = m__io->read_u2be();
    m_thumbnail_x = m__io->read_u1();
    m_thumbnail_y = m__io->read_u1();
    m_thumbnail = m__io->read_bytes(((thumbnail_x() * thumbnail_y()) * 3));
}

jpeg_t::segment_app0_t::~segment_app0_t() {
}

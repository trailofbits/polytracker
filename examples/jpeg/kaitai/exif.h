#ifndef EXIF_H_
#define EXIF_H_

// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "kaitai/kaitaistruct.h"

#include <stdint.h>

#if KAITAI_STRUCT_VERSION < 7000L
#error "Incompatible Kaitai Struct C++/STL API: version 0.7 or later is required"
#endif
class exif_be_t;
class exif_le_t;

class exif_t : public kaitai::kstruct {

public:

    exif_t(kaitai::kstream* p__io, kaitai::kstruct* p__parent = 0, exif_t* p__root = 0);

private:
    void _read();

public:
    ~exif_t();

private:
    uint16_t m_endianness;
    kaitai::kstruct* m_body;
    bool n_body;

public:
    bool _is_null_body() { body(); return n_body; };

private:
    exif_t* m__root;
    kaitai::kstruct* m__parent;

public:
    uint16_t endianness() const { return m_endianness; }
    kaitai::kstruct* body() const { return m_body; }
    exif_t* _root() const { return m__root; }
    kaitai::kstruct* _parent() const { return m__parent; }
};

#endif  // EXIF_H_

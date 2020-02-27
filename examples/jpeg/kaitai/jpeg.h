#ifndef JPEG_H_
#define JPEG_H_

// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "kaitai/kaitaistruct.h"

#include <stdint.h>
#include <vector>

#if KAITAI_STRUCT_VERSION < 7000L
#error "Incompatible Kaitai Struct C++/STL API: version 0.7 or later is required"
#endif
class exif_t;

class jpeg_t : public kaitai::kstruct {

public:
    class segment_t;
    class segment_sos_t;
    class segment_app1_t;
    class segment_sof0_t;
    class exif_in_jpeg_t;
    class segment_app0_t;

    enum component_id_t {
        COMPONENT_ID_Y = 1,
        COMPONENT_ID_CB = 2,
        COMPONENT_ID_CR = 3,
        COMPONENT_ID_I = 4,
        COMPONENT_ID_Q = 5
    };

    jpeg_t(kaitai::kstream* p__io, kaitai::kstruct* p__parent = 0, jpeg_t* p__root = 0);

private:
    void _read();

public:
    ~jpeg_t();

    class segment_t : public kaitai::kstruct {

    public:

        enum marker_enum_t {
            MARKER_ENUM_TEM = 1,
            MARKER_ENUM_SOF0 = 192,
            MARKER_ENUM_SOF1 = 193,
            MARKER_ENUM_SOF2 = 194,
            MARKER_ENUM_SOF3 = 195,
            MARKER_ENUM_DHT = 196,
            MARKER_ENUM_SOF5 = 197,
            MARKER_ENUM_SOF6 = 198,
            MARKER_ENUM_SOF7 = 199,
            MARKER_ENUM_SOI = 216,
            MARKER_ENUM_EOI = 217,
            MARKER_ENUM_SOS = 218,
            MARKER_ENUM_DQT = 219,
            MARKER_ENUM_DNL = 220,
            MARKER_ENUM_DRI = 221,
            MARKER_ENUM_DHP = 222,
            MARKER_ENUM_APP0 = 224,
            MARKER_ENUM_APP1 = 225,
            MARKER_ENUM_APP2 = 226,
            MARKER_ENUM_APP3 = 227,
            MARKER_ENUM_APP4 = 228,
            MARKER_ENUM_APP5 = 229,
            MARKER_ENUM_APP6 = 230,
            MARKER_ENUM_APP7 = 231,
            MARKER_ENUM_APP8 = 232,
            MARKER_ENUM_APP9 = 233,
            MARKER_ENUM_APP10 = 234,
            MARKER_ENUM_APP11 = 235,
            MARKER_ENUM_APP12 = 236,
            MARKER_ENUM_APP13 = 237,
            MARKER_ENUM_APP14 = 238,
            MARKER_ENUM_APP15 = 239,
            MARKER_ENUM_COM = 254
        };

        segment_t(kaitai::kstream* p__io, jpeg_t* p__parent = 0, jpeg_t* p__root = 0);

    private:
        void _read();

    public:
        ~segment_t();

    private:
        std::string m_magic;
        marker_enum_t m_marker;
        uint16_t m_length;
        bool n_length;

    public:
        bool _is_null_length() { length(); return n_length; };

    private:
        kaitai::kstruct* m_data;
        bool n_data;

    public:
        bool _is_null_data() { data(); return n_data; };

    private:
        std::string m_image_data;
        bool n_image_data;

    public:
        bool _is_null_image_data() { image_data(); return n_image_data; };

    private:
        jpeg_t* m__root;
        jpeg_t* m__parent;
        std::string m__raw_data;
        kaitai::kstream* m__io__raw_data;

    public:
        std::string magic() const { return m_magic; }
        marker_enum_t marker() const { return m_marker; }
        uint16_t length() const { return m_length; }
        kaitai::kstruct* data() const { return m_data; }
        std::string image_data() const { return m_image_data; }
        jpeg_t* _root() const { return m__root; }
        jpeg_t* _parent() const { return m__parent; }
        std::string _raw_data() const { return m__raw_data; }
        kaitai::kstream* _io__raw_data() const { return m__io__raw_data; }
    };

    class segment_sos_t : public kaitai::kstruct {

    public:
        class component_t;

        segment_sos_t(kaitai::kstream* p__io, jpeg_t::segment_t* p__parent = 0, jpeg_t* p__root = 0);

    private:
        void _read();

    public:
        ~segment_sos_t();

        class component_t : public kaitai::kstruct {

        public:

            component_t(kaitai::kstream* p__io, jpeg_t::segment_sos_t* p__parent = 0, jpeg_t* p__root = 0);

        private:
            void _read();

        public:
            ~component_t();

        private:
            component_id_t m_id;
            uint8_t m_huffman_table;
            jpeg_t* m__root;
            jpeg_t::segment_sos_t* m__parent;

        public:

            /**
             * Scan component selector
             */
            component_id_t id() const { return m_id; }
            uint8_t huffman_table() const { return m_huffman_table; }
            jpeg_t* _root() const { return m__root; }
            jpeg_t::segment_sos_t* _parent() const { return m__parent; }
        };

    private:
        uint8_t m_num_components;
        std::vector<component_t*>* m_components;
        uint8_t m_start_spectral_selection;
        uint8_t m_end_spectral;
        uint8_t m_appr_bit_pos;
        jpeg_t* m__root;
        jpeg_t::segment_t* m__parent;

    public:

        /**
         * Number of components in scan
         */
        uint8_t num_components() const { return m_num_components; }

        /**
         * Scan components specification
         */
        std::vector<component_t*>* components() const { return m_components; }

        /**
         * Start of spectral selection or predictor selection
         */
        uint8_t start_spectral_selection() const { return m_start_spectral_selection; }

        /**
         * End of spectral selection
         */
        uint8_t end_spectral() const { return m_end_spectral; }

        /**
         * Successive approximation bit position high + Successive approximation bit position low or point transform
         */
        uint8_t appr_bit_pos() const { return m_appr_bit_pos; }
        jpeg_t* _root() const { return m__root; }
        jpeg_t::segment_t* _parent() const { return m__parent; }
    };

    class segment_app1_t : public kaitai::kstruct {

    public:

        segment_app1_t(kaitai::kstream* p__io, jpeg_t::segment_t* p__parent = 0, jpeg_t* p__root = 0);

    private:
        void _read();

    public:
        ~segment_app1_t();

    private:
        std::string m_magic;
        exif_in_jpeg_t* m_body;
        bool n_body;

    public:
        bool _is_null_body() { body(); return n_body; };

    private:
        jpeg_t* m__root;
        jpeg_t::segment_t* m__parent;

    public:
        std::string magic() const { return m_magic; }
        exif_in_jpeg_t* body() const { return m_body; }
        jpeg_t* _root() const { return m__root; }
        jpeg_t::segment_t* _parent() const { return m__parent; }
    };

    class segment_sof0_t : public kaitai::kstruct {

    public:
        class component_t;

        segment_sof0_t(kaitai::kstream* p__io, jpeg_t::segment_t* p__parent = 0, jpeg_t* p__root = 0);

    private:
        void _read();

    public:
        ~segment_sof0_t();

        class component_t : public kaitai::kstruct {

        public:

            component_t(kaitai::kstream* p__io, jpeg_t::segment_sof0_t* p__parent = 0, jpeg_t* p__root = 0);

        private:
            void _read();

        public:
            ~component_t();

        private:
            bool f_sampling_x;
            int32_t m_sampling_x;

        public:
            int32_t sampling_x();

        private:
            bool f_sampling_y;
            int32_t m_sampling_y;

        public:
            int32_t sampling_y();

        private:
            component_id_t m_id;
            uint8_t m_sampling_factors;
            uint8_t m_quantization_table_id;
            jpeg_t* m__root;
            jpeg_t::segment_sof0_t* m__parent;

        public:

            /**
             * Component selector
             */
            component_id_t id() const { return m_id; }
            uint8_t sampling_factors() const { return m_sampling_factors; }
            uint8_t quantization_table_id() const { return m_quantization_table_id; }
            jpeg_t* _root() const { return m__root; }
            jpeg_t::segment_sof0_t* _parent() const { return m__parent; }
        };

    private:
        uint8_t m_bits_per_sample;
        uint16_t m_image_height;
        uint16_t m_image_width;
        uint8_t m_num_components;
        std::vector<component_t*>* m_components;
        jpeg_t* m__root;
        jpeg_t::segment_t* m__parent;

    public:
        uint8_t bits_per_sample() const { return m_bits_per_sample; }
        uint16_t image_height() const { return m_image_height; }
        uint16_t image_width() const { return m_image_width; }
        uint8_t num_components() const { return m_num_components; }
        std::vector<component_t*>* components() const { return m_components; }
        jpeg_t* _root() const { return m__root; }
        jpeg_t::segment_t* _parent() const { return m__parent; }
    };

    class exif_in_jpeg_t : public kaitai::kstruct {

    public:

        exif_in_jpeg_t(kaitai::kstream* p__io, jpeg_t::segment_app1_t* p__parent = 0, jpeg_t* p__root = 0);

    private:
        void _read();

    public:
        ~exif_in_jpeg_t();

    private:
        std::string m_extra_zero;
        exif_t* m_data;
        jpeg_t* m__root;
        jpeg_t::segment_app1_t* m__parent;
        std::string m__raw_data;
        kaitai::kstream* m__io__raw_data;

    public:
        std::string extra_zero() const { return m_extra_zero; }
        exif_t* data() const { return m_data; }
        jpeg_t* _root() const { return m__root; }
        jpeg_t::segment_app1_t* _parent() const { return m__parent; }
        std::string _raw_data() const { return m__raw_data; }
        kaitai::kstream* _io__raw_data() const { return m__io__raw_data; }
    };

    class segment_app0_t : public kaitai::kstruct {

    public:

        enum density_unit_t {
            DENSITY_UNIT_NO_UNITS = 0,
            DENSITY_UNIT_PIXELS_PER_INCH = 1,
            DENSITY_UNIT_PIXELS_PER_CM = 2
        };

        segment_app0_t(kaitai::kstream* p__io, jpeg_t::segment_t* p__parent = 0, jpeg_t* p__root = 0);

    private:
        void _read();

    public:
        ~segment_app0_t();

    private:
        std::string m_magic;
        uint8_t m_version_major;
        uint8_t m_version_minor;
        density_unit_t m_density_units;
        uint16_t m_density_x;
        uint16_t m_density_y;
        uint8_t m_thumbnail_x;
        uint8_t m_thumbnail_y;
        std::string m_thumbnail;
        jpeg_t* m__root;
        jpeg_t::segment_t* m__parent;

    public:
        std::string magic() const { return m_magic; }
        uint8_t version_major() const { return m_version_major; }
        uint8_t version_minor() const { return m_version_minor; }
        density_unit_t density_units() const { return m_density_units; }

        /**
         * Horizontal pixel density. Must not be zero.
         */
        uint16_t density_x() const { return m_density_x; }

        /**
         * Vertical pixel density. Must not be zero.
         */
        uint16_t density_y() const { return m_density_y; }

        /**
         * Horizontal pixel count of the following embedded RGB thumbnail. May be zero.
         */
        uint8_t thumbnail_x() const { return m_thumbnail_x; }

        /**
         * Vertical pixel count of the following embedded RGB thumbnail. May be zero.
         */
        uint8_t thumbnail_y() const { return m_thumbnail_y; }

        /**
         * Uncompressed 24 bit RGB (8 bits per color channel) raster thumbnail data in the order R0, G0, B0, ... Rn, Gn, Bn
         */
        std::string thumbnail() const { return m_thumbnail; }
        jpeg_t* _root() const { return m__root; }
        jpeg_t::segment_t* _parent() const { return m__parent; }
    };

private:
    std::vector<segment_t*>* m_segments;
    jpeg_t* m__root;
    kaitai::kstruct* m__parent;

public:
    std::vector<segment_t*>* segments() const { return m_segments; }
    jpeg_t* _root() const { return m__root; }
    kaitai::kstruct* _parent() const { return m__parent; }
};

#endif  // JPEG_H_

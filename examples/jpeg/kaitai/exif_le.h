#ifndef EXIF_LE_H_
#define EXIF_LE_H_

// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

#include "kaitai/kaitaistruct.h"

#include <stdint.h>
#include <vector>

#if KAITAI_STRUCT_VERSION < 7000L
#error "Incompatible Kaitai Struct C++/STL API: version 0.7 or later is required"
#endif

class exif_le_t : public kaitai::kstruct {

public:
    class ifd_t;
    class ifd_field_t;

    exif_le_t(kaitai::kstream* p__io, kaitai::kstruct* p__parent = 0, exif_le_t* p__root = 0);

private:
    void _read();

public:
    ~exif_le_t();

    class ifd_t : public kaitai::kstruct {

    public:

        ifd_t(kaitai::kstream* p__io, kaitai::kstruct* p__parent = 0, exif_le_t* p__root = 0);

    private:
        void _read();

    public:
        ~ifd_t();

    private:
        bool f_next_ifd;
        ifd_t* m_next_ifd;
        bool n_next_ifd;

    public:
        bool _is_null_next_ifd() { next_ifd(); return n_next_ifd; };

    private:

    public:
        ifd_t* next_ifd();

    private:
        uint16_t m_num_fields;
        std::vector<ifd_field_t*>* m_fields;
        uint32_t m_next_ifd_ofs;
        exif_le_t* m__root;
        kaitai::kstruct* m__parent;

    public:
        uint16_t num_fields() const { return m_num_fields; }
        std::vector<ifd_field_t*>* fields() const { return m_fields; }
        uint32_t next_ifd_ofs() const { return m_next_ifd_ofs; }
        exif_le_t* _root() const { return m__root; }
        kaitai::kstruct* _parent() const { return m__parent; }
    };

    class ifd_field_t : public kaitai::kstruct {

    public:

        enum field_type_enum_t {
            FIELD_TYPE_ENUM_BYTE = 1,
            FIELD_TYPE_ENUM_ASCII_STRING = 2,
            FIELD_TYPE_ENUM_WORD = 3,
            FIELD_TYPE_ENUM_DWORD = 4,
            FIELD_TYPE_ENUM_RATIONAL = 5,
            FIELD_TYPE_ENUM_UNDEFINED = 7,
            FIELD_TYPE_ENUM_SLONG = 9,
            FIELD_TYPE_ENUM_SRATIONAL = 10
        };

        enum tag_enum_t {
            TAG_ENUM_IMAGE_WIDTH = 256,
            TAG_ENUM_IMAGE_HEIGHT = 257,
            TAG_ENUM_BITS_PER_SAMPLE = 258,
            TAG_ENUM_COMPRESSION = 259,
            TAG_ENUM_PHOTOMETRIC_INTERPRETATION = 262,
            TAG_ENUM_THRESHOLDING = 263,
            TAG_ENUM_CELL_WIDTH = 264,
            TAG_ENUM_CELL_LENGTH = 265,
            TAG_ENUM_FILL_ORDER = 266,
            TAG_ENUM_DOCUMENT_NAME = 269,
            TAG_ENUM_IMAGE_DESCRIPTION = 270,
            TAG_ENUM_MAKE = 271,
            TAG_ENUM_MODEL = 272,
            TAG_ENUM_STRIP_OFFSETS = 273,
            TAG_ENUM_ORIENTATION = 274,
            TAG_ENUM_SAMPLES_PER_PIXEL = 277,
            TAG_ENUM_ROWS_PER_STRIP = 278,
            TAG_ENUM_STRIP_BYTE_COUNTS = 279,
            TAG_ENUM_MIN_SAMPLE_VALUE = 280,
            TAG_ENUM_MAX_SAMPLE_VALUE = 281,
            TAG_ENUM_X_RESOLUTION = 282,
            TAG_ENUM_Y_RESOLUTION = 283,
            TAG_ENUM_PLANAR_CONFIGURATION = 284,
            TAG_ENUM_PAGE_NAME = 285,
            TAG_ENUM_X_POSITION = 286,
            TAG_ENUM_Y_POSITION = 287,
            TAG_ENUM_FREE_OFFSETS = 288,
            TAG_ENUM_FREE_BYTE_COUNTS = 289,
            TAG_ENUM_GRAY_RESPONSE_UNIT = 290,
            TAG_ENUM_GRAY_RESPONSE_CURVE = 291,
            TAG_ENUM_T4_OPTIONS = 292,
            TAG_ENUM_T6_OPTIONS = 293,
            TAG_ENUM_RESOLUTION_UNIT = 296,
            TAG_ENUM_PAGE_NUMBER = 297,
            TAG_ENUM_COLOR_RESPONSE_UNIT = 300,
            TAG_ENUM_TRANSFER_FUNCTION = 301,
            TAG_ENUM_SOFTWARE = 305,
            TAG_ENUM_MODIFY_DATE = 306,
            TAG_ENUM_ARTIST = 315,
            TAG_ENUM_HOST_COMPUTER = 316,
            TAG_ENUM_PREDICTOR = 317,
            TAG_ENUM_WHITE_POINT = 318,
            TAG_ENUM_PRIMARY_CHROMATICITIES = 319,
            TAG_ENUM_COLOR_MAP = 320,
            TAG_ENUM_HALFTONE_HINTS = 321,
            TAG_ENUM_TILE_WIDTH = 322,
            TAG_ENUM_TILE_LENGTH = 323,
            TAG_ENUM_TILE_OFFSETS = 324,
            TAG_ENUM_TILE_BYTE_COUNTS = 325,
            TAG_ENUM_BAD_FAX_LINES = 326,
            TAG_ENUM_CLEAN_FAX_DATA = 327,
            TAG_ENUM_CONSECUTIVE_BAD_FAX_LINES = 328,
            TAG_ENUM_SUB_IFD = 330,
            TAG_ENUM_INK_SET = 332,
            TAG_ENUM_INK_NAMES = 333,
            TAG_ENUM_NUMBEROF_INKS = 334,
            TAG_ENUM_DOT_RANGE = 336,
            TAG_ENUM_TARGET_PRINTER = 337,
            TAG_ENUM_EXTRA_SAMPLES = 338,
            TAG_ENUM_SAMPLE_FORMAT = 339,
            TAG_ENUM_S_MIN_SAMPLE_VALUE = 340,
            TAG_ENUM_S_MAX_SAMPLE_VALUE = 341,
            TAG_ENUM_TRANSFER_RANGE = 342,
            TAG_ENUM_CLIP_PATH = 343,
            TAG_ENUM_X_CLIP_PATH_UNITS = 344,
            TAG_ENUM_Y_CLIP_PATH_UNITS = 345,
            TAG_ENUM_INDEXED = 346,
            TAG_ENUM_JPEG_TABLES = 347,
            TAG_ENUM_OPI_PROXY = 351,
            TAG_ENUM_GLOBAL_PARAMETERS_IFD = 400,
            TAG_ENUM_PROFILE_TYPE = 401,
            TAG_ENUM_FAX_PROFILE = 402,
            TAG_ENUM_CODING_METHODS = 403,
            TAG_ENUM_VERSION_YEAR = 404,
            TAG_ENUM_MODE_NUMBER = 405,
            TAG_ENUM_DECODE = 433,
            TAG_ENUM_DEFAULT_IMAGE_COLOR = 434,
            TAG_ENUM_T82_OPTIONS = 435,
            TAG_ENUM_JPEG_TABLES2 = 437,
            TAG_ENUM_JPEG_PROC = 512,
            TAG_ENUM_THUMBNAIL_OFFSET = 513,
            TAG_ENUM_THUMBNAIL_LENGTH = 514,
            TAG_ENUM_JPEG_RESTART_INTERVAL = 515,
            TAG_ENUM_JPEG_LOSSLESS_PREDICTORS = 517,
            TAG_ENUM_JPEG_POINT_TRANSFORMS = 518,
            TAG_ENUM_JPEGQ_TABLES = 519,
            TAG_ENUM_JPEGDC_TABLES = 520,
            TAG_ENUM_JPEGAC_TABLES = 521,
            TAG_ENUM_Y_CB_CR_COEFFICIENTS = 529,
            TAG_ENUM_Y_CB_CR_SUB_SAMPLING = 530,
            TAG_ENUM_Y_CB_CR_POSITIONING = 531,
            TAG_ENUM_REFERENCE_BLACK_WHITE = 532,
            TAG_ENUM_STRIP_ROW_COUNTS = 559,
            TAG_ENUM_APPLICATION_NOTES = 700,
            TAG_ENUM_USPTO_MISCELLANEOUS = 999,
            TAG_ENUM_RELATED_IMAGE_FILE_FORMAT = 4096,
            TAG_ENUM_RELATED_IMAGE_WIDTH = 4097,
            TAG_ENUM_RELATED_IMAGE_HEIGHT = 4098,
            TAG_ENUM_RATING = 18246,
            TAG_ENUM_XP_DIP_XML = 18247,
            TAG_ENUM_STITCH_INFO = 18248,
            TAG_ENUM_RATING_PERCENT = 18249,
            TAG_ENUM_SONY_RAW_FILE_TYPE = 28672,
            TAG_ENUM_LIGHT_FALLOFF_PARAMS = 28722,
            TAG_ENUM_CHROMATIC_ABERRATION_CORR_PARAMS = 28725,
            TAG_ENUM_DISTORTION_CORR_PARAMS = 28727,
            TAG_ENUM_IMAGE_ID = 32781,
            TAG_ENUM_WANG_TAG1 = 32931,
            TAG_ENUM_WANG_ANNOTATION = 32932,
            TAG_ENUM_WANG_TAG3 = 32933,
            TAG_ENUM_WANG_TAG4 = 32934,
            TAG_ENUM_IMAGE_REFERENCE_POINTS = 32953,
            TAG_ENUM_REGION_XFORM_TACK_POINT = 32954,
            TAG_ENUM_WARP_QUADRILATERAL = 32955,
            TAG_ENUM_AFFINE_TRANSFORM_MAT = 32956,
            TAG_ENUM_MATTEING = 32995,
            TAG_ENUM_DATA_TYPE = 32996,
            TAG_ENUM_IMAGE_DEPTH = 32997,
            TAG_ENUM_TILE_DEPTH = 32998,
            TAG_ENUM_IMAGE_FULL_WIDTH = 33300,
            TAG_ENUM_IMAGE_FULL_HEIGHT = 33301,
            TAG_ENUM_TEXTURE_FORMAT = 33302,
            TAG_ENUM_WRAP_MODES = 33303,
            TAG_ENUM_FOV_COT = 33304,
            TAG_ENUM_MATRIX_WORLD_TO_SCREEN = 33305,
            TAG_ENUM_MATRIX_WORLD_TO_CAMERA = 33306,
            TAG_ENUM_MODEL2 = 33405,
            TAG_ENUM_CFA_REPEAT_PATTERN_DIM = 33421,
            TAG_ENUM_CFA_PATTERN2 = 33422,
            TAG_ENUM_BATTERY_LEVEL = 33423,
            TAG_ENUM_KODAK_IFD = 33424,
            TAG_ENUM_COPYRIGHT = 33432,
            TAG_ENUM_EXPOSURE_TIME = 33434,
            TAG_ENUM_F_NUMBER = 33437,
            TAG_ENUM_MD_FILE_TAG = 33445,
            TAG_ENUM_MD_SCALE_PIXEL = 33446,
            TAG_ENUM_MD_COLOR_TABLE = 33447,
            TAG_ENUM_MD_LAB_NAME = 33448,
            TAG_ENUM_MD_SAMPLE_INFO = 33449,
            TAG_ENUM_MD_PREP_DATE = 33450,
            TAG_ENUM_MD_PREP_TIME = 33451,
            TAG_ENUM_MD_FILE_UNITS = 33452,
            TAG_ENUM_PIXEL_SCALE = 33550,
            TAG_ENUM_ADVENT_SCALE = 33589,
            TAG_ENUM_ADVENT_REVISION = 33590,
            TAG_ENUM_UIC1_TAG = 33628,
            TAG_ENUM_UIC2_TAG = 33629,
            TAG_ENUM_UIC3_TAG = 33630,
            TAG_ENUM_UIC4_TAG = 33631,
            TAG_ENUM_IPTC_NAA = 33723,
            TAG_ENUM_INTERGRAPH_PACKET_DATA = 33918,
            TAG_ENUM_INTERGRAPH_FLAG_REGISTERS = 33919,
            TAG_ENUM_INTERGRAPH_MATRIX = 33920,
            TAG_ENUM_INGR_RESERVED = 33921,
            TAG_ENUM_MODEL_TIE_POINT = 33922,
            TAG_ENUM_SITE = 34016,
            TAG_ENUM_COLOR_SEQUENCE = 34017,
            TAG_ENUM_IT8_HEADER = 34018,
            TAG_ENUM_RASTER_PADDING = 34019,
            TAG_ENUM_BITS_PER_RUN_LENGTH = 34020,
            TAG_ENUM_BITS_PER_EXTENDED_RUN_LENGTH = 34021,
            TAG_ENUM_COLOR_TABLE = 34022,
            TAG_ENUM_IMAGE_COLOR_INDICATOR = 34023,
            TAG_ENUM_BACKGROUND_COLOR_INDICATOR = 34024,
            TAG_ENUM_IMAGE_COLOR_VALUE = 34025,
            TAG_ENUM_BACKGROUND_COLOR_VALUE = 34026,
            TAG_ENUM_PIXEL_INTENSITY_RANGE = 34027,
            TAG_ENUM_TRANSPARENCY_INDICATOR = 34028,
            TAG_ENUM_COLOR_CHARACTERIZATION = 34029,
            TAG_ENUM_HC_USAGE = 34030,
            TAG_ENUM_TRAP_INDICATOR = 34031,
            TAG_ENUM_CMYK_EQUIVALENT = 34032,
            TAG_ENUM_SEM_INFO = 34118,
            TAG_ENUM_AFCP_IPTC = 34152,
            TAG_ENUM_PIXEL_MAGIC_JBIG_OPTIONS = 34232,
            TAG_ENUM_JPL_CARTO_IFD = 34263,
            TAG_ENUM_MODEL_TRANSFORM = 34264,
            TAG_ENUM_WB_GRGB_LEVELS = 34306,
            TAG_ENUM_LEAF_DATA = 34310,
            TAG_ENUM_PHOTOSHOP_SETTINGS = 34377,
            TAG_ENUM_EXIF_OFFSET = 34665,
            TAG_ENUM_ICC_PROFILE = 34675,
            TAG_ENUM_TIFF_FX_EXTENSIONS = 34687,
            TAG_ENUM_MULTI_PROFILES = 34688,
            TAG_ENUM_SHARED_DATA = 34689,
            TAG_ENUM_T88_OPTIONS = 34690,
            TAG_ENUM_IMAGE_LAYER = 34732,
            TAG_ENUM_GEO_TIFF_DIRECTORY = 34735,
            TAG_ENUM_GEO_TIFF_DOUBLE_PARAMS = 34736,
            TAG_ENUM_GEO_TIFF_ASCII_PARAMS = 34737,
            TAG_ENUM_JBIG_OPTIONS = 34750,
            TAG_ENUM_EXPOSURE_PROGRAM = 34850,
            TAG_ENUM_SPECTRAL_SENSITIVITY = 34852,
            TAG_ENUM_GPS_INFO = 34853,
            TAG_ENUM_ISO = 34855,
            TAG_ENUM_OPTO_ELECTRIC_CONV_FACTOR = 34856,
            TAG_ENUM_INTERLACE = 34857,
            TAG_ENUM_TIME_ZONE_OFFSET = 34858,
            TAG_ENUM_SELF_TIMER_MODE = 34859,
            TAG_ENUM_SENSITIVITY_TYPE = 34864,
            TAG_ENUM_STANDARD_OUTPUT_SENSITIVITY = 34865,
            TAG_ENUM_RECOMMENDED_EXPOSURE_INDEX = 34866,
            TAG_ENUM_ISO_SPEED = 34867,
            TAG_ENUM_ISO_SPEED_LATITUDEYYY = 34868,
            TAG_ENUM_ISO_SPEED_LATITUDEZZZ = 34869,
            TAG_ENUM_FAX_RECV_PARAMS = 34908,
            TAG_ENUM_FAX_SUB_ADDRESS = 34909,
            TAG_ENUM_FAX_RECV_TIME = 34910,
            TAG_ENUM_FEDEX_EDR = 34929,
            TAG_ENUM_LEAF_SUB_IFD = 34954,
            TAG_ENUM_EXIF_VERSION = 36864,
            TAG_ENUM_DATE_TIME_ORIGINAL = 36867,
            TAG_ENUM_CREATE_DATE = 36868,
            TAG_ENUM_GOOGLE_PLUS_UPLOAD_CODE = 36873,
            TAG_ENUM_OFFSET_TIME = 36880,
            TAG_ENUM_OFFSET_TIME_ORIGINAL = 36881,
            TAG_ENUM_OFFSET_TIME_DIGITIZED = 36882,
            TAG_ENUM_COMPONENTS_CONFIGURATION = 37121,
            TAG_ENUM_COMPRESSED_BITS_PER_PIXEL = 37122,
            TAG_ENUM_SHUTTER_SPEED_VALUE = 37377,
            TAG_ENUM_APERTURE_VALUE = 37378,
            TAG_ENUM_BRIGHTNESS_VALUE = 37379,
            TAG_ENUM_EXPOSURE_COMPENSATION = 37380,
            TAG_ENUM_MAX_APERTURE_VALUE = 37381,
            TAG_ENUM_SUBJECT_DISTANCE = 37382,
            TAG_ENUM_METERING_MODE = 37383,
            TAG_ENUM_LIGHT_SOURCE = 37384,
            TAG_ENUM_FLASH = 37385,
            TAG_ENUM_FOCAL_LENGTH = 37386,
            TAG_ENUM_FLASH_ENERGY = 37387,
            TAG_ENUM_SPATIAL_FREQUENCY_RESPONSE = 37388,
            TAG_ENUM_NOISE = 37389,
            TAG_ENUM_FOCAL_PLANE_X_RESOLUTION = 37390,
            TAG_ENUM_FOCAL_PLANE_Y_RESOLUTION = 37391,
            TAG_ENUM_FOCAL_PLANE_RESOLUTION_UNIT = 37392,
            TAG_ENUM_IMAGE_NUMBER = 37393,
            TAG_ENUM_SECURITY_CLASSIFICATION = 37394,
            TAG_ENUM_IMAGE_HISTORY = 37395,
            TAG_ENUM_SUBJECT_AREA = 37396,
            TAG_ENUM_EXPOSURE_INDEX = 37397,
            TAG_ENUM_TIFF_EP_STANDARD_ID = 37398,
            TAG_ENUM_SENSING_METHOD = 37399,
            TAG_ENUM_CIP3_DATA_FILE = 37434,
            TAG_ENUM_CIP3_SHEET = 37435,
            TAG_ENUM_CIP3_SIDE = 37436,
            TAG_ENUM_STO_NITS = 37439,
            TAG_ENUM_MAKER_NOTE = 37500,
            TAG_ENUM_USER_COMMENT = 37510,
            TAG_ENUM_SUB_SEC_TIME = 37520,
            TAG_ENUM_SUB_SEC_TIME_ORIGINAL = 37521,
            TAG_ENUM_SUB_SEC_TIME_DIGITIZED = 37522,
            TAG_ENUM_MS_DOCUMENT_TEXT = 37679,
            TAG_ENUM_MS_PROPERTY_SET_STORAGE = 37680,
            TAG_ENUM_MS_DOCUMENT_TEXT_POSITION = 37681,
            TAG_ENUM_IMAGE_SOURCE_DATA = 37724,
            TAG_ENUM_AMBIENT_TEMPERATURE = 37888,
            TAG_ENUM_HUMIDITY = 37889,
            TAG_ENUM_PRESSURE = 37890,
            TAG_ENUM_WATER_DEPTH = 37891,
            TAG_ENUM_ACCELERATION = 37892,
            TAG_ENUM_CAMERA_ELEVATION_ANGLE = 37893,
            TAG_ENUM_XP_TITLE = 40091,
            TAG_ENUM_XP_COMMENT = 40092,
            TAG_ENUM_XP_AUTHOR = 40093,
            TAG_ENUM_XP_KEYWORDS = 40094,
            TAG_ENUM_XP_SUBJECT = 40095,
            TAG_ENUM_FLASHPIX_VERSION = 40960,
            TAG_ENUM_COLOR_SPACE = 40961,
            TAG_ENUM_EXIF_IMAGE_WIDTH = 40962,
            TAG_ENUM_EXIF_IMAGE_HEIGHT = 40963,
            TAG_ENUM_RELATED_SOUND_FILE = 40964,
            TAG_ENUM_INTEROP_OFFSET = 40965,
            TAG_ENUM_SAMSUNG_RAW_POINTERS_OFFSET = 40976,
            TAG_ENUM_SAMSUNG_RAW_POINTERS_LENGTH = 40977,
            TAG_ENUM_SAMSUNG_RAW_BYTE_ORDER = 41217,
            TAG_ENUM_SAMSUNG_RAW_UNKNOWN = 41218,
            TAG_ENUM_FLASH_ENERGY2 = 41483,
            TAG_ENUM_SPATIAL_FREQUENCY_RESPONSE2 = 41484,
            TAG_ENUM_NOISE2 = 41485,
            TAG_ENUM_FOCAL_PLANE_X_RESOLUTION2 = 41486,
            TAG_ENUM_FOCAL_PLANE_Y_RESOLUTION2 = 41487,
            TAG_ENUM_FOCAL_PLANE_RESOLUTION_UNIT2 = 41488,
            TAG_ENUM_IMAGE_NUMBER2 = 41489,
            TAG_ENUM_SECURITY_CLASSIFICATION2 = 41490,
            TAG_ENUM_IMAGE_HISTORY2 = 41491,
            TAG_ENUM_SUBJECT_LOCATION = 41492,
            TAG_ENUM_EXPOSURE_INDEX2 = 41493,
            TAG_ENUM_TIFF_EP_STANDARD_ID2 = 41494,
            TAG_ENUM_SENSING_METHOD2 = 41495,
            TAG_ENUM_FILE_SOURCE = 41728,
            TAG_ENUM_SCENE_TYPE = 41729,
            TAG_ENUM_CFA_PATTERN = 41730,
            TAG_ENUM_CUSTOM_RENDERED = 41985,
            TAG_ENUM_EXPOSURE_MODE = 41986,
            TAG_ENUM_WHITE_BALANCE = 41987,
            TAG_ENUM_DIGITAL_ZOOM_RATIO = 41988,
            TAG_ENUM_FOCAL_LENGTH_IN35MM_FORMAT = 41989,
            TAG_ENUM_SCENE_CAPTURE_TYPE = 41990,
            TAG_ENUM_GAIN_CONTROL = 41991,
            TAG_ENUM_CONTRAST = 41992,
            TAG_ENUM_SATURATION = 41993,
            TAG_ENUM_SHARPNESS = 41994,
            TAG_ENUM_DEVICE_SETTING_DESCRIPTION = 41995,
            TAG_ENUM_SUBJECT_DISTANCE_RANGE = 41996,
            TAG_ENUM_IMAGE_UNIQUE_ID = 42016,
            TAG_ENUM_OWNER_NAME = 42032,
            TAG_ENUM_SERIAL_NUMBER = 42033,
            TAG_ENUM_LENS_INFO = 42034,
            TAG_ENUM_LENS_MAKE = 42035,
            TAG_ENUM_LENS_MODEL = 42036,
            TAG_ENUM_LENS_SERIAL_NUMBER = 42037,
            TAG_ENUM_GDAL_METADATA = 42112,
            TAG_ENUM_GDAL_NO_DATA = 42113,
            TAG_ENUM_GAMMA = 42240,
            TAG_ENUM_EXPAND_SOFTWARE = 44992,
            TAG_ENUM_EXPAND_LENS = 44993,
            TAG_ENUM_EXPAND_FILM = 44994,
            TAG_ENUM_EXPAND_FILTER_LENS = 44995,
            TAG_ENUM_EXPAND_SCANNER = 44996,
            TAG_ENUM_EXPAND_FLASH_LAMP = 44997,
            TAG_ENUM_PIXEL_FORMAT = 48129,
            TAG_ENUM_TRANSFORMATION = 48130,
            TAG_ENUM_UNCOMPRESSED = 48131,
            TAG_ENUM_IMAGE_TYPE = 48132,
            TAG_ENUM_IMAGE_WIDTH2 = 48256,
            TAG_ENUM_IMAGE_HEIGHT2 = 48257,
            TAG_ENUM_WIDTH_RESOLUTION = 48258,
            TAG_ENUM_HEIGHT_RESOLUTION = 48259,
            TAG_ENUM_IMAGE_OFFSET = 48320,
            TAG_ENUM_IMAGE_BYTE_COUNT = 48321,
            TAG_ENUM_ALPHA_OFFSET = 48322,
            TAG_ENUM_ALPHA_BYTE_COUNT = 48323,
            TAG_ENUM_IMAGE_DATA_DISCARD = 48324,
            TAG_ENUM_ALPHA_DATA_DISCARD = 48325,
            TAG_ENUM_OCE_SCANJOB_DESC = 50215,
            TAG_ENUM_OCE_APPLICATION_SELECTOR = 50216,
            TAG_ENUM_OCE_ID_NUMBER = 50217,
            TAG_ENUM_OCE_IMAGE_LOGIC = 50218,
            TAG_ENUM_ANNOTATIONS = 50255,
            TAG_ENUM_PRINT_IM = 50341,
            TAG_ENUM_ORIGINAL_FILE_NAME = 50547,
            TAG_ENUM_USPTO_ORIGINAL_CONTENT_TYPE = 50560,
            TAG_ENUM_DNG_VERSION = 50706,
            TAG_ENUM_DNG_BACKWARD_VERSION = 50707,
            TAG_ENUM_UNIQUE_CAMERA_MODEL = 50708,
            TAG_ENUM_LOCALIZED_CAMERA_MODEL = 50709,
            TAG_ENUM_CFA_PLANE_COLOR = 50710,
            TAG_ENUM_CFA_LAYOUT = 50711,
            TAG_ENUM_LINEARIZATION_TABLE = 50712,
            TAG_ENUM_BLACK_LEVEL_REPEAT_DIM = 50713,
            TAG_ENUM_BLACK_LEVEL = 50714,
            TAG_ENUM_BLACK_LEVEL_DELTA_H = 50715,
            TAG_ENUM_BLACK_LEVEL_DELTA_V = 50716,
            TAG_ENUM_WHITE_LEVEL = 50717,
            TAG_ENUM_DEFAULT_SCALE = 50718,
            TAG_ENUM_DEFAULT_CROP_ORIGIN = 50719,
            TAG_ENUM_DEFAULT_CROP_SIZE = 50720,
            TAG_ENUM_COLOR_MATRIX1 = 50721,
            TAG_ENUM_COLOR_MATRIX2 = 50722,
            TAG_ENUM_CAMERA_CALIBRATION1 = 50723,
            TAG_ENUM_CAMERA_CALIBRATION2 = 50724,
            TAG_ENUM_REDUCTION_MATRIX1 = 50725,
            TAG_ENUM_REDUCTION_MATRIX2 = 50726,
            TAG_ENUM_ANALOG_BALANCE = 50727,
            TAG_ENUM_AS_SHOT_NEUTRAL = 50728,
            TAG_ENUM_AS_SHOT_WHITE_XY = 50729,
            TAG_ENUM_BASELINE_EXPOSURE = 50730,
            TAG_ENUM_BASELINE_NOISE = 50731,
            TAG_ENUM_BASELINE_SHARPNESS = 50732,
            TAG_ENUM_BAYER_GREEN_SPLIT = 50733,
            TAG_ENUM_LINEAR_RESPONSE_LIMIT = 50734,
            TAG_ENUM_CAMERA_SERIAL_NUMBER = 50735,
            TAG_ENUM_DNG_LENS_INFO = 50736,
            TAG_ENUM_CHROMA_BLUR_RADIUS = 50737,
            TAG_ENUM_ANTI_ALIAS_STRENGTH = 50738,
            TAG_ENUM_SHADOW_SCALE = 50739,
            TAG_ENUM_SR2_PRIVATE = 50740,
            TAG_ENUM_MAKER_NOTE_SAFETY = 50741,
            TAG_ENUM_RAW_IMAGE_SEGMENTATION = 50752,
            TAG_ENUM_CALIBRATION_ILLUMINANT1 = 50778,
            TAG_ENUM_CALIBRATION_ILLUMINANT2 = 50779,
            TAG_ENUM_BEST_QUALITY_SCALE = 50780,
            TAG_ENUM_RAW_DATA_UNIQUE_ID = 50781,
            TAG_ENUM_ALIAS_LAYER_METADATA = 50784,
            TAG_ENUM_ORIGINAL_RAW_FILE_NAME = 50827,
            TAG_ENUM_ORIGINAL_RAW_FILE_DATA = 50828,
            TAG_ENUM_ACTIVE_AREA = 50829,
            TAG_ENUM_MASKED_AREAS = 50830,
            TAG_ENUM_AS_SHOT_ICC_PROFILE = 50831,
            TAG_ENUM_AS_SHOT_PRE_PROFILE_MATRIX = 50832,
            TAG_ENUM_CURRENT_ICC_PROFILE = 50833,
            TAG_ENUM_CURRENT_PRE_PROFILE_MATRIX = 50834,
            TAG_ENUM_COLORIMETRIC_REFERENCE = 50879,
            TAG_ENUM_S_RAW_TYPE = 50885,
            TAG_ENUM_PANASONIC_TITLE = 50898,
            TAG_ENUM_PANASONIC_TITLE2 = 50899,
            TAG_ENUM_CAMERA_CALIBRATION_SIG = 50931,
            TAG_ENUM_PROFILE_CALIBRATION_SIG = 50932,
            TAG_ENUM_PROFILE_IFD = 50933,
            TAG_ENUM_AS_SHOT_PROFILE_NAME = 50934,
            TAG_ENUM_NOISE_REDUCTION_APPLIED = 50935,
            TAG_ENUM_PROFILE_NAME = 50936,
            TAG_ENUM_PROFILE_HUE_SAT_MAP_DIMS = 50937,
            TAG_ENUM_PROFILE_HUE_SAT_MAP_DATA1 = 50938,
            TAG_ENUM_PROFILE_HUE_SAT_MAP_DATA2 = 50939,
            TAG_ENUM_PROFILE_TONE_CURVE = 50940,
            TAG_ENUM_PROFILE_EMBED_POLICY = 50941,
            TAG_ENUM_PROFILE_COPYRIGHT = 50942,
            TAG_ENUM_FORWARD_MATRIX1 = 50964,
            TAG_ENUM_FORWARD_MATRIX2 = 50965,
            TAG_ENUM_PREVIEW_APPLICATION_NAME = 50966,
            TAG_ENUM_PREVIEW_APPLICATION_VERSION = 50967,
            TAG_ENUM_PREVIEW_SETTINGS_NAME = 50968,
            TAG_ENUM_PREVIEW_SETTINGS_DIGEST = 50969,
            TAG_ENUM_PREVIEW_COLOR_SPACE = 50970,
            TAG_ENUM_PREVIEW_DATE_TIME = 50971,
            TAG_ENUM_RAW_IMAGE_DIGEST = 50972,
            TAG_ENUM_ORIGINAL_RAW_FILE_DIGEST = 50973,
            TAG_ENUM_SUB_TILE_BLOCK_SIZE = 50974,
            TAG_ENUM_ROW_INTERLEAVE_FACTOR = 50975,
            TAG_ENUM_PROFILE_LOOK_TABLE_DIMS = 50981,
            TAG_ENUM_PROFILE_LOOK_TABLE_DATA = 50982,
            TAG_ENUM_OPCODE_LIST1 = 51008,
            TAG_ENUM_OPCODE_LIST2 = 51009,
            TAG_ENUM_OPCODE_LIST3 = 51022,
            TAG_ENUM_NOISE_PROFILE = 51041,
            TAG_ENUM_TIME_CODES = 51043,
            TAG_ENUM_FRAME_RATE = 51044,
            TAG_ENUM_T_STOP = 51058,
            TAG_ENUM_REEL_NAME = 51081,
            TAG_ENUM_ORIGINAL_DEFAULT_FINAL_SIZE = 51089,
            TAG_ENUM_ORIGINAL_BEST_QUALITY_SIZE = 51090,
            TAG_ENUM_ORIGINAL_DEFAULT_CROP_SIZE = 51091,
            TAG_ENUM_CAMERA_LABEL = 51105,
            TAG_ENUM_PROFILE_HUE_SAT_MAP_ENCODING = 51107,
            TAG_ENUM_PROFILE_LOOK_TABLE_ENCODING = 51108,
            TAG_ENUM_BASELINE_EXPOSURE_OFFSET = 51109,
            TAG_ENUM_DEFAULT_BLACK_RENDER = 51110,
            TAG_ENUM_NEW_RAW_IMAGE_DIGEST = 51111,
            TAG_ENUM_RAW_TO_PREVIEW_GAIN = 51112,
            TAG_ENUM_DEFAULT_USER_CROP = 51125,
            TAG_ENUM_PADDING = 59932,
            TAG_ENUM_OFFSET_SCHEMA = 59933,
            TAG_ENUM_OWNER_NAME2 = 65000,
            TAG_ENUM_SERIAL_NUMBER2 = 65001,
            TAG_ENUM_LENS = 65002,
            TAG_ENUM_KDC_IFD = 65024,
            TAG_ENUM_RAW_FILE = 65100,
            TAG_ENUM_CONVERTER = 65101,
            TAG_ENUM_WHITE_BALANCE2 = 65102,
            TAG_ENUM_EXPOSURE = 65105,
            TAG_ENUM_SHADOWS = 65106,
            TAG_ENUM_BRIGHTNESS = 65107,
            TAG_ENUM_CONTRAST2 = 65108,
            TAG_ENUM_SATURATION2 = 65109,
            TAG_ENUM_SHARPNESS2 = 65110,
            TAG_ENUM_SMOOTHNESS = 65111,
            TAG_ENUM_MOIRE_FILTER = 65112
        };

        ifd_field_t(kaitai::kstream* p__io, exif_le_t::ifd_t* p__parent = 0, exif_le_t* p__root = 0);

    private:
        void _read();

    public:
        ~ifd_field_t();

    private:
        bool f_type_byte_length;
        int8_t m_type_byte_length;

    public:
        int8_t type_byte_length();

    private:
        bool f_byte_length;
        int32_t m_byte_length;

    public:
        int32_t byte_length();

    private:
        bool f_is_immediate_data;
        bool m_is_immediate_data;

    public:
        bool is_immediate_data();

    private:
        bool f_data;
        std::string m_data;
        bool n_data;

    public:
        bool _is_null_data() { data(); return n_data; };

    private:

    public:
        std::string data();

    private:
        tag_enum_t m_tag;
        field_type_enum_t m_field_type;
        uint32_t m_length;
        uint32_t m_ofs_or_data;
        exif_le_t* m__root;
        exif_le_t::ifd_t* m__parent;

    public:
        tag_enum_t tag() const { return m_tag; }
        field_type_enum_t field_type() const { return m_field_type; }
        uint32_t length() const { return m_length; }
        uint32_t ofs_or_data() const { return m_ofs_or_data; }
        exif_le_t* _root() const { return m__root; }
        exif_le_t::ifd_t* _parent() const { return m__parent; }
    };

private:
    bool f_ifd0;
    ifd_t* m_ifd0;

public:
    ifd_t* ifd0();

private:
    uint16_t m_version;
    uint32_t m_ifd0_ofs;
    exif_le_t* m__root;
    kaitai::kstruct* m__parent;

public:
    uint16_t version() const { return m_version; }
    uint32_t ifd0_ofs() const { return m_ifd0_ofs; }
    exif_le_t* _root() const { return m__root; }
    kaitai::kstruct* _parent() const { return m__parent; }
};

#endif  // EXIF_LE_H_

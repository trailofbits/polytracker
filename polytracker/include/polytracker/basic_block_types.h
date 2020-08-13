#ifndef POLYTRACKER_INCLUDE_POLYTRACKER_BASIC_BLOCK_TYPES_H_
#define POLYTRACKER_INCLUDE_POLYTRACKER_BASIC_BLOCK_TYPES_H_

namespace polytracker {

#define ENABLE_BITMASK_OPERATOR(EnumClass, oper) \
constexpr EnumClass operator oper(EnumClass lhs, EnumClass rhs) { \
  using underlying = typename std::underlying_type<EnumClass>::type; \
  return static_cast<EnumClass> ( \
    static_cast<underlying>(lhs) oper static_cast<underlying>(rhs) \
  ); \
}
#define ENABLE_BITMASK_OPERATORS(EnumClass) \
ENABLE_BITMASK_OPERATOR(EnumClass, |)

enum struct BasicBlockType : uint8_t {
  UNKNOWN = 0,
  STANDARD = 1,
  CONDITIONAL = 2,
  LOOP_ENTRY = 4,
  LOOP_EXIT = 8,
  FUNCTION_ENTRY = 16,
  FUNCTION_RETURN = 32
};
ENABLE_BITMASK_OPERATORS(BasicBlockType)

};

#endif /* POLYTRACKER_INCLUDE_POLYTRACKER_BASIC_BLOCK_TYPES_H_ */

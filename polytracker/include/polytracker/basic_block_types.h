#ifndef POLYTRACKER_INCLUDE_POLYTRACKER_BASIC_BLOCK_TYPES_H_
#define POLYTRACKER_INCLUDE_POLYTRACKER_BASIC_BLOCK_TYPES_H_

namespace polytracker {

#define ENABLE_BITMASK_OPERATOR(EnumClass, oper)                               \
  constexpr EnumClass operator oper(const EnumClass lhs,                       \
                                    const EnumClass rhs) {                     \
    using underlying = typename std::underlying_type<EnumClass>::type;         \
    return static_cast<EnumClass>(static_cast<underlying>(lhs)                 \
                                      oper static_cast<underlying>(rhs));      \
  }
#define ENABLE_BITMASK_OPERATORS(EnumClass)                                    \
  ENABLE_BITMASK_OPERATOR(EnumClass, |)                                        \
  ENABLE_BITMASK_OPERATOR(EnumClass, &)                                        \
  ENABLE_BITMASK_OPERATOR(EnumClass, ^)

enum struct BasicBlockType : uint8_t {
  UNKNOWN = 0,
  STANDARD = 1,
  CONDITIONAL = 2,
  LOOP_ENTRY = 4,
  LOOP_EXIT = 8,
  FUNCTION_ENTRY = 16,
  FUNCTION_RETURN = 32,
};
ENABLE_BITMASK_OPERATORS(BasicBlockType)

#if __cplusplus < 201402L
#define ENABLE_IF_CPP14(X)
#else
#define ENABLE_IF_CPP14(X) X
#endif

ENABLE_IF_CPP14(constexpr)
bool hasType(BasicBlockType toCheck, BasicBlockType type) {
  if (type == BasicBlockType::UNKNOWN) {
    return toCheck == type;
  } else {
    return (toCheck & type) != BasicBlockType::UNKNOWN;
  }
}

}; // namespace polytracker

#endif /* POLYTRACKER_INCLUDE_POLYTRACKER_BASIC_BLOCK_TYPES_H_ */

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
  UNKNOWN = 0,     // we don't know what kind of BB this is
  STANDARD = 1,    // this is a standard, unremarkable BB
  CONDITIONAL = 2, // this BB contains a conditional branch
  LOOP_ENTRY = 6,  // this BB is an entrypoint into a loop (implies CONDITIONAL)
  LOOP_EXIT = 10,  // this BB exits a loop (implies CONDITIONAL)
  FUNCTION_ENTRY = 16,  // this BB is the first in a function
  FUNCTION_EXIT = 32,   // this BB contains a function return
  FUNCTION_RETURN = 64, // this BB is executed immediately after a CallInst
  FUNCTION_CALL = 128,  // this BB contains a CallInst
};
ENABLE_BITMASK_OPERATORS(BasicBlockType)

#if __cplusplus < 201402L
#define ENABLE_IF_CPP14(X)
#define ENABLE_IF_NOT_CPP14(X) X
#else
#define ENABLE_IF_CPP14(X) X
#define ENABLE_IF_NOT_CPP14(X)
#endif

ENABLE_IF_CPP14(constexpr)
ENABLE_IF_NOT_CPP14(inline)
bool hasType(BasicBlockType toCheck, BasicBlockType type) {
  if (type == BasicBlockType::UNKNOWN) {
    return toCheck == type;
  } else {
    return (toCheck & type) != BasicBlockType::UNKNOWN;
  }
}

}; // namespace polytracker

#endif /* POLYTRACKER_INCLUDE_POLYTRACKER_BASIC_BLOCK_TYPES_H_ */

#ifndef EARLY_CONSTRUCT_HPP_
#define EARLY_CONSTRUCT_HPP_

#include <type_traits>
#include <utility>

// Helpers for early construction
// The macros and template methods used have been tuned to give equal
// performance as a global variable (at least in -O3). Invoking get typically
// results in a lea of symbol address. This is equal to having a global
// variable.
namespace early_construct_details {

template <typename T>
using storage_type = typename std::aligned_storage<sizeof(T), alignof(T)>::type;

template <typename T>
__attribute__((always_inline)) T &
get(typename std::aligned_storage<sizeof(T), alignof(T)>::type &src) {
  return reinterpret_cast<T &>(src);
}

template <typename T, typename... Args>
__attribute__((always_inline)) void
construct(typename std::aligned_storage<sizeof(T), alignof(T)>::type &dst,
          Args &&...args) {
  ::new (&dst) T(std::forward<Args>(args)...);
}

} // namespace early_construct_details

#define EARLY_CONSTRUCT_EXTERN_STORAGE(TYPE, NAME)                             \
  extern early_construct_details::storage_type<TYPE> NAME;

// Defines the getter-function for early construction
// Results in a function get_NAME() -> TYPE&
#define EARLY_CONSTRUCT_GETTER(TYPE, NAME)                                     \
  __attribute__((always_inline)) static auto &get_##NAME() {                   \
    return early_construct_details::get<TYPE>(NAME);                           \
  }

// Creates a getter-function using external declared variable name
// if the getter is needed in a different module
#define EARLY_CONSTRUCT_EXTERN_GETTER(TYPE, NAME)                              \
  EARLY_CONSTRUCT_EXTERN_STORAGE(TYPE, NAME)                                   \
  __attribute__((always_inline)) static auto &get_##NAME() {                   \
    return early_construct_details::get<TYPE>(NAME);                           \
  }

// Declares storage for early construction
#define EARLY_CONSTRUCT_STORAGE(TYPE, NAME)                                    \
  early_construct_details::storage_type<TYPE> NAME;

// Declare a variable named NAME, which is suitable to hold and
// early-constructed type TYPE. Provide additional getters for the value. Before
// getters can be used, the variable must be initialized via the
// DO_EARLY_DEFAULT_CONSTRUCT or DO_EARLY_CONSTRUCT macros.
#define DECLARE_EARLY_CONSTRUCT(TYPE, NAME)                                    \
  EARLY_CONSTRUCT_STORAGE(TYPE, NAME)                                          \
  EARLY_CONSTRUCT_GETTER(TYPE, NAME)

// Default constructs a variable name NAME to hold a type TYPE.
// Accesses to the variable as TYPE uses the getter method:
// get_NAME() -> TYPE&
#define DO_EARLY_DEFAULT_CONSTRUCT(TYPE, NAME)                                 \
  early_construct_details::construct<TYPE>(NAME);

// Constructs a variable name NAME to hold a type TYPE using constructor args.
// Accesses to the variable as TYPE uses the getter method:
// get_NAME() -> TYPE&
#define DO_EARLY_CONSTRUCT(TYPE, NAME, ...)                                    \
  early_construct_details::construct<TYPE>(NAME, __VA_ARGS__);

// Create a variable named NAME, holding a type TYPE is early constructed
// using default construction.
// TODO: Consider if it shall be possible to use preinit_array as well?
#define GLOBAL_EARLY_DEFAULT_CONSTRUCT(TYPE, NAME)                             \
  DECLARE_EARLY_CONSTRUCT(TYPE, NAME)                                          \
  namespace {                                                                  \
  __attribute__((constructor)) static void global_early_construct_##NAME() {   \
    DO_EARLY_DEFAULT_CONSTRUCT(TYPE, NAME)                                     \
  }                                                                            \
  }

// Create a variable named NAME, holding a type TYPE is early constructed
// using arguments.
// TODO: Consider if it shall be possible to use preinit_array as well?
#define GLOBAL_EARLY_CONSTRUCT(TYPE, NAME, ...)                                \
  DECLARE_EARLY_CONSTRUCT(TYPE, NAME)                                          \
  namespace {                                                                  \
  __attribute__((constructor)) static void global_early_construct_##NAME() {   \
    DO_EARLY_CONSTRUCT(TYPE, NAME, __VA_ARGS__)                                \
  }                                                                            \
  }

// TODO: enable destruction for early constructed global objects as well.:w

#endif

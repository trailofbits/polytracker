#ifndef GIGAFUNCTION_TYPES_H
#define GIGAFUNCTION_TYPES_H
#include <cstdint>
#include <variant>

namespace gigafunction {

using thread_state_handle = void *;
using thread_id = uint32_t;
using block_id = uint32_t;
using event_id = uint64_t;

struct block_enter {
  block_enter(event_id e, block_id b) : eid{e}, bid{b} {}
  event_id eid;
  block_id bid;
};

struct openfd {
  event_id eid;
  int fd;
};

struct closefd {
  event_id eid;
  int fd;
};

using event = std::variant<std::monostate, block_enter, openfd, closefd>;

} // namespace gigafunction

#endif
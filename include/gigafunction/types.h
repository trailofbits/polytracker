#ifndef GIGAFUNCTION_TYPES_H
#define GIGAFUNCTION_TYPES_H
#include <cstdint>
#include <string>
#include <variant>

namespace gigafunction {

using thread_state_handle = void *;
using thread_id = uint32_t;
using block_id = uint32_t;
using event_id = uint64_t;

namespace events {
struct block_enter {
  block_enter(thread_id t, event_id e, block_id b) : tid{t}, eid{e}, bid{b} {}
  thread_id tid;
  event_id eid;
  block_id bid;
};

struct open {
  open(thread_id tid, event_id eid, int fd, std::string path) : tid{tid}, eid(eid), fd(fd), path(path) {}
  thread_id tid;
  event_id eid;
  int fd;
  std::string path;
};

struct close {
  close(thread_id tid, event_id eid, int fd) : tid(tid), eid(eid), fd(fd) {}
  thread_id tid;
  event_id eid;
  int fd;
};

struct read {
  read(thread_id tid, event_id e, int fd, size_t offset, size_t len)
      : tid(tid), eid(e), fd(fd), offset(offset), len(len) {}
  thread_id tid;
  event_id eid;
  int fd;
  size_t offset;
  size_t len;
};

} // namespace events

using event = std::variant<std::monostate, events::block_enter, events::open,
                           events::close, events::read>;

} // namespace gigafunction

#endif
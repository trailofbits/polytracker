#ifndef GIGAFUNCTION_EVENT_HELPER_HPP
#define GIGAFUNCTION_EVENT_HELPER_HPP

#include <cassert>
#include <cstdlib>

#include "gigafunction/types.h"


// This file containts helper functions only used during testing

namespace gigafunction {

namespace events {
inline bool operator==(block_enter const &l, block_enter const &r) {
  return l.tid == r.tid && l.eid == r.eid && l.bid == r.bid;
}

inline bool operator==(open const &l, open const &r) {
  return l.tid == r.tid && l.eid == r.eid && l.fd == r.fd && l.path == r.path;
}

inline bool operator==(close const &l, close const &r) {
  return l.tid == r.tid && l.eid == r.eid && l.fd == r.fd;
}

inline bool operator==(read const &l, read const &r) {
  return l.tid == r.tid && l.eid == r.eid && l.fd == r.fd && l.offset == r.offset && l.len == r.len;
}

}

// Create a random event
inline event random_event(size_t max_strlen=1024) {
  auto evindex = rand() % (std::variant_size_v<event> -1); // -1, skip monostate
  switch(evindex) {
    case 0: return events::block_enter(rand(), rand(), rand());
    case 1: return events::open(rand(), rand(), rand(), std::string(rand() % max_strlen, static_cast<char>(rand())));
    case 2: return events::close(rand(), rand(), rand());
    case 3: return events::read(rand(), rand(), rand(), rand(), rand());
    default: assert(false && "Test case not updated for new event types"); 
  }
  return {};
}

}
#endif
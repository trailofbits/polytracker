#include <optional>
#include <type_traits>
#include <variant>

#include "gigafunction/types.h"
#include "gigafunction/traceio/varint.h"

namespace gigafunction {
  namespace detail {
    // Details, helper methods to do the actual serialization/deserialization of data
    template<typename It, typename T>
    std::optional<It> encode_field(It dst, It dstend, T const &val) {
      return varint::encode(dst, dstend, val);
    }

    template<typename It>
    std::optional<It> encode_field(It dst, It dstend, std::string const &val) {
      if (auto res = encode_field(dst, dstend, val.size())) {
        auto n = std::distance(res.value(), dstend);
        if (n < 0 || static_cast<std::string::size_type>(n) < val.size())
          return {};
        return std::copy(val.begin(), val.end(), res.value());
      }
      return {};
    }
    
    template<typename It, typename Arg, typename... Args>
    std::optional<It> serialize_fields(It dst, It dstend, Arg const &arg, Args const& ...args) {
      if constexpr(sizeof...(Args) == 0)
        return encode_field(dst, dstend, arg);
      else {
        if (auto res = encode_field(dst, dstend, arg))
          return serialize_fields(res.value(), dstend, args...);
        return {}; 
      }
    }

    template<typename Variant, typename T, size_t Index = 0>
    constexpr size_t variant_index() {
      if constexpr (Index == std::variant_size_v<Variant>) {  return Index; }
      else if constexpr(std::is_same_v<T, std::variant_alternative_t<Index, Variant>>) { return Index; }
      else return variant_index<Variant, T, Index+1>();
    }


    template<typename It, typename T>
    std::optional<It> decode_field(It src, It srcend, T &dst) {
      return varint::decode(src, srcend, dst);
    }

    template<typename It>
    std::optional<It> decode_field(It src, It srcend, std::string &dst) {
      std::string::size_type len;
      if (auto res = varint::decode(src, srcend, len)) {
        auto remain = std::distance(res.value(), srcend);
        if (remain < 0 || static_cast<std::string::size_type>(remain) < len)
          return {};
        dst = std::string(reinterpret_cast<char const*>(&*res.value()), len);
        return res.value() + len;
      }
      return {};
    }

    template<typename It, typename T, size_t I, typename... Fields>
    std::optional<It> deserialize_one(It src, It srcend, event &e, std::tuple<Fields...> &values) {
      if (auto res = decode_field(src, srcend, std::get<I>(values))) {
        if constexpr (I == sizeof...(Fields)-1) { // Last field was ok, construct event type
          e = std::make_from_tuple<T>(std::move(values));
          return res;
        } else {
          return deserialize_one<It, T, I+1, Fields...>(res.value(), srcend, e, values);
        }
      }
      return {};
    }

    template<typename It, typename T, typename... Fields>
    std::optional<It> deserialize_type(It src, It srcend, event &e) {
      std::tuple<Fields...> values;
      return deserialize_one<It, T, 0, Fields...>(src, srcend, e, values);
    }
  }


  template<typename It>
  std::optional<It> serialize_event(It dst, It dstend, event const &e) {
    struct visitor {
      It dst;
      It dstend;
      size_t index;

      visitor(It dst, It dstend, size_t index) : dst(dst), dstend(dstend), index(index) {}

      std::optional<It> operator()(events::block_enter const &evblock) {
        return detail::serialize_fields(dst, dstend, index, evblock.tid, evblock.eid, evblock.bid);
      }

      std::optional<It> operator()(events::open const &evopen) {
        return detail::serialize_fields(dst, dstend, index, evopen.tid, evopen.eid, evopen.fd, evopen.path);
      }

      std::optional<It> operator()(events::close const &evclose) {
        return detail::serialize_fields(dst, dstend, index, evclose.tid, evclose.eid, evclose.fd);
      }

      std::optional<It> operator()(events::read const &evread) {
        return detail::serialize_fields(dst, dstend, index, evread.tid, evread.eid, evread.fd, evread.offset, evread.len);
      }

      std::optional<It> operator()(std::monostate const &) {
        assert(false && "BUG: Serialize invoked on a monostate event");
        return {};
      }
    };

    return std::visit(visitor(dst, dstend, e.index()), e);
  }



  template<typename It>
  std::optional<It> deserialize_event(It src, It srcend, event &e) {
    size_t index;

    if (auto res = varint::decode(src, srcend, index)) {
      switch(index) {
        case detail::variant_index<event, events::block_enter>():
          return detail::deserialize_type<It, events::block_enter, thread_id, event_id, block_id>(res.value(), srcend, e);
        case detail::variant_index<event, events::close>():
          return detail::deserialize_type<It, events::close, thread_id, event_id, int>(res.value(), srcend, e);
        case detail::variant_index<event, events::open>():
          return detail::deserialize_type<It, events::open, thread_id, event_id, int, std::string>(res.value(), srcend, e);
        case detail::variant_index<event, events::read>():
          return detail::deserialize_type<It, events::read, thread_id, event_id, int,  size_t, size_t>(res.value(), srcend, e);
        default:
          assert(false && "Invalid event type");
      }
    }
    return {};

  }

}
#include <algorithm>
#include <cstdint>
#include <optional>
#include <type_traits>

namespace gigafunction {

  namespace varint {
    template<typename T>
    struct max_storage {
      enum {
        value = (sizeof(T)*8-1)/7+1,
        unused_bits = value * (8-1) - sizeof(T) *8
      };
    };

    namespace detail {
      // Overflow check and 0x80 bit clear in one go.
      template<typename It, typename T>
      bool invalid_last_byte(It last) {
        auto mask = static_cast<uint8_t>(0xff) << (8 - (max_storage<T>::unused_bits+1));
        return (mask & *last);
      }

      // If RangeOK there is enough data to decode, omit range check
      template<bool CheckRange, typename It, typename T, size_t I, size_t N>
      struct dec {
        static std::optional<It> one_byte(It begin, It end, T&dst) {
          if constexpr(CheckRange) {
            if (begin == end)
              return {};
          }

          dst |= static_cast<T>(*begin & 0x7f) << (I * 7);
          if (*begin > 0x7f)
            return dec<CheckRange, It, T, I+1, N-1>::one_byte(std::next(begin), end, dst);
          else
            return {std::next(begin)};
        }
      };
 
      template<bool CheckRange, typename It, typename T, size_t I>
      struct dec<CheckRange, It, T, I, 0> {
        static std::optional<It> one_byte(It begin, It end, T&dst) {
          if constexpr(CheckRange) {
            if (begin == end)
              return {};
          }

          if (invalid_last_byte<It, T>(begin))
            return {};
 
          auto const mask = static_cast<uint8_t>(0xff) >> (max_storage<T>::unused_bits+1);
          dst |= static_cast<T>(*begin & mask) << (I * 7);
          return {std::next(begin)};
        }
      };

      template<bool CheckRange, typename It, typename T, size_t N>
      struct enc {
        static std::optional<It> one_byte(It dst, It dstend, T src) {
          if constexpr(CheckRange) {
            if (dst == dstend)
              return {};
          }

          if (src > 0x7f) {
            *dst = static_cast<uint8_t>((src & 0x7f) | 0x80);
            return enc<CheckRange, It, T, N-1>::one_byte(std::next(dst), dstend, src >> 7);
          } else {
            return enc<false, It, T, 0>::one_byte(dst, dstend, src);
          }
        }
      };

      template<bool CheckRange, typename It, typename T>
      struct enc<CheckRange, It, T, 0> {
        static std::optional<It> one_byte(It dst, It dstend, T src) {
          if constexpr (CheckRange) {
            if (dst == dstend)
              return {};
          }

          assert((src <=0x7f) && "BUG: Last byte value too large!");
          *dst = static_cast<uint8_t>(src);
          return std::next(dst);
        }
      };
    }

    template<typename It, typename T>
    std::optional<It> encode(It dst, It dstend, T src) {
      auto n = std::distance(dst, dstend);
      assert((n>=0) && "BUG: Destination range invalid");
      if (n>= max_storage<T>::value)
        return detail::enc<false, It, T, max_storage<T>::value-1>::one_byte(dst, dstend, src);
      else
        return detail::enc<true, It, T, max_storage<T>::value-1>::one_byte(dst, dstend, src);
    }



    template<typename It, typename T>
    std::optional<It> decode(It src, It srcend, T& dst) {
      dst = 0;
      auto maxlen = max_storage<T>::value;
      auto d = std::distance(src, srcend);
      assert((d >= 0) && "Invalid decode iterators");
      if (d >=maxlen)
        return detail::dec<false, It, T, 0, max_storage<T>::value-1>::one_byte(src, srcend, dst);
      else
        return detail::dec<true, It, T, 0, max_storage<T>::value-1>::one_byte(src, srcend, dst);
    }
  } // namespace varint
}
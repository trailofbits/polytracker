#ifndef TDAG_UTIL_HPP
#define TDAG_UTIL_HPP
#include <cstdio>
#include <functional>
#include <optional>

namespace util {
template <typename T, typename Tuple> struct TypeIndex;

// Determines the index of a type T in a Tuple
template <typename T, typename... Types>
struct TypeIndex<T, std::tuple<Types...>> {
  static constexpr std::size_t index = []() {
    constexpr std::array<bool, sizeof...(Types)> eq{
        {(std::is_same_v<Types, T>)...}};
    const auto it = std::find(eq.begin(), eq.end(), true);
    if (it == eq.end())
      std::runtime_error("Type is not in type sequnce");
    return std::distance(eq.begin(), it);
  }();
};

inline void dump_range(std::string name, std::span<uint8_t> range) {
  auto begin = reinterpret_cast<uintptr_t>(&*range.begin());
  auto end = reinterpret_cast<uintptr_t>(&*range.end());
  printf("Name: %s begin: %lx end: %lx\n", name.data(), begin, end);
}
} // namespace util

// TODO(hbrodin): Quick and dirty impl of map. Could be considerably improved.
template <typename T, typename F>
auto map(std::optional<T> o, F &&f)
    -> std::optional<std::invoke_result_t<F, T &>> {
  if (o)
    return std::invoke(std::forward<F>(f), *o);
  else
    return {};
}

#endif
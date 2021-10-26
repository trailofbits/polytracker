#ifndef GIGAFUNCTION_SPSC_BUFFER
#define GIGAFUNCTION_SPSC_BUFFER

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <optional>
#include <type_traits>

namespace gigafunction {


// A very simple single producer single consumer lock free bounded buffer
template<typename T, size_t N>
class spsc_buffer {
  static_assert(N > 2, "N must be larger than two");
  // TODO (hbrodin): Could allow copy-constructible as well. Just fix the get-functions.
  static_assert(std::is_move_constructible_v<T>, "T must be move constructible");
public:

  using aligned_storage_t = std::aligned_storage_t<sizeof(T), alignof(T)>;

  template<typename U>
  void put(U&& u);

  T get();
  std::optional<T> try_get();

  size_t get_n(T* dst, size_t n);

  template<size_t DstLen>
  size_t get_n(aligned_storage_t (&dst)[DstLen]);

  bool empty() const;
  bool full() const;

  constexpr size_t capacity() const {
    return N-1; // Need one slot free to differentiate between empty/full
  }

private:
  // Increment a value and wrap by N
  size_t wrapping_increment(size_t val) const;

  // Uninitialized storage
  aligned_storage_t buf_[N];
  std::atomic<size_t> write_{0};
  std::atomic<size_t> read_{0};
};


template<typename T, size_t N>
size_t spsc_buffer<T,N>::wrapping_increment(size_t val) const {
  // If power of two N faster wrap
  if constexpr((N & (N-1)) == 0) {
    return (val + 1) & (N-1);
  } else {
    return (val +1) % N;
  }
}

template<typename T, size_t N>
bool spsc_buffer<T,N>::empty() const {
  return write_.load(std::memory_order_relaxed) == read_.load(std::memory_order_relaxed);
}

template<typename T, size_t N>
bool spsc_buffer<T,N>::full() const {
  return wrapping_increment(write_.load(std::memory_order_relaxed)) == read_.load(std::memory_order_relaxed);
}

template<typename T, size_t N>
template<typename U>
void spsc_buffer<T,N>::put(U&& u) {
  auto write = write_.load(std::memory_order_relaxed);
  auto next = wrapping_increment(write);
  // While queue full (synchronizes with read_ release in get)
  while (next == read_.load(std::memory_order_acquire)) {} // Currently just spinning, consider yielding (perhaps via policy).
  // TODO (hbrodin): See busy loop in get as well.

  // Construct
  ::new (&buf_[write]) T(std::forward<U>(u));
  // and then publish
  write_.store(next, std::memory_order_release);
}

template<typename T, size_t N>
T spsc_buffer<T,N>::get() {
  auto read = read_.load(std::memory_order_relaxed);
  // While queue empty (synchronizes with write_ release in put)
  while (read == write_.load(std::memory_order_acquire)) {} // TODO (hbrodin): Might be able to speed up with a relaxed load in the loop and an acquire load after...
  // Move from/destroy in-buffer value
  T t = std::move(reinterpret_cast<T&>(buf_[read]));
  reinterpret_cast<T&>(buf_[read]).~T();

  read_.store(wrapping_increment(read), std::memory_order_release);

  return t;
}

template<typename T, size_t N>
std::optional<T> spsc_buffer<T,N>::try_get() {
  auto read = read_.load(std::memory_order_relaxed);
  // If queue empty (synchronizes with write_ release in put)
  if (read == write_.load(std::memory_order_acquire))
    return {};
  // Move from/destroy in-buffer value
  std::optional<T> t(std::move(reinterpret_cast<T&>(buf_[read])));
  reinterpret_cast<T&>(buf_[read]).~T();

  read_.store(wrapping_increment(read), std::memory_order_release);

  return t;
}

template<typename T, size_t N>
size_t spsc_buffer<T,N>::get_n(T* dst, size_t n) {
  auto read = read_.load(std::memory_order_relaxed);
  auto write = write_.load(std::memory_order_acquire);

  size_t count = 0;
  for (;read !=write && count != n;read = wrapping_increment(read), count++) {
    *(dst + count) = std::move(reinterpret_cast<T&>(buf_[read]));
    reinterpret_cast<T&>(buf_[read]).~T();
  }
  read_.store(read, std::memory_order_release);
  return count;

}

#if 0
// TODO (hbrodin): This will be instantiated for each DstLen, consider
// common base class to collect majority of the functionality to reduce code bloat.
template<typename T, size_t N>
template<size_t DstLen>
size_t spsc_buffer<T,N>::get_n(aligned_storage_t (&dst)[DstLen]) {
  // TODO (hbrodin): One could implement a loop over the below cases untill DstLen is consumed
  static_assert(DstLen < N-1, "Current implementation can't handle larger dst than max capacity");

  auto read = read_.load(std::memory_order_relaxed);
  auto write = write_.load(std::memory_order_acquire);
  auto read_start = reinterpret_cast<T*>(&buf_[read]);

  auto dst_start = reinterpret_cast<T*>(dst);

  // Wrapped case
  if (write < read) { // 
    // Read all elements untill end of array
    size_t copy_count = std::min(DstLen, (N-read));
    std::uninitialized_move_n(read_start, copy_count, dst_start);
    std::destroy_n(read_start, copy_count);
    // Read remaining elements from beginning of array (if any)
    size_t remaining = std::min(DstLen-copy_count, write);
    read_start = reinterpret_cast<T*>(buf_);
    std::uninitialized_move_n(read_start, remaining, dst_start+copy_count);
    std::destroy_n(read_start, remaining);
    read_.store(wrapping_increment(read + copy_count + remaining), std::memory_order_release);
    return copy_count + remaining;

  } else { // Non-wrapped case
    size_t copy_count = std::min(DstLen, (write-read));
    std::uninitialized_move_n(read_start, copy_count, dst_start);
    std::destroy_n(read_start, copy_count);
    read_.store(read + copy_count, std::memory_order_release);
    return copy_count;

  }
}

#endif

}

#endif
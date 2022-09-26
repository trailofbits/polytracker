#ifndef TDAG_SECTION_HPP
#define TDAG_SECTION_HPP

#include <mutex>
#include <optional>
#include <span>

#include "error.hpp"
#include "taintdag/util.hpp"

namespace taintdag {

// Optional Base class for sections.
// Provide a number of convenience methods, e.g. for
// allocation of data within the allocated range (rng in ctor).
// Also, provides required accessor method for how much memory
// was used.
class SectionBase {
public:
  using span_t = std::span<uint8_t>;

  SectionBase(span_t rng) : mem_(rng), write_it_{mem_.begin()} {}

  // Returns the number of bytes used by this section
  size_t size() const {
    std::unique_lock<std::mutex> l{m_};
    return std::distance(mem_.begin(), write_it_);
  }

protected:
  // A write context allows writes to the section.
  // The WriteCtx is acquired via the write()-method, which ensures proper
  // locking is in place as long as a reference to the WriteCtx is held, access
  // to mem is exclusive.
  struct WriteCtx {
    WriteCtx(span_t m, std::unique_lock<std::mutex> l)
        : mem{m}, l_{std::move(l)} {}
    span_t mem;

  private:
    std::unique_lock<std::mutex> l_;
  };

  // Returns a WriteCtx instance with the lock held after successfull
  // allocation. Callers have exclusive access for the life time of
  // WriteCtx.
  // N.b. size() competes for the same lock.
  [[nodiscard]] std::optional<WriteCtx> write(size_t allocation_size) {
    std::unique_lock<std::mutex> l{m_};

    auto new_write_it = write_it_ + allocation_size;

    // Out of bounds or wrapping allocation?
    if (new_write_it > mem_.end() || new_write_it < write_it_) {
      return {};
    }

    // Allocation ok, return a write ptr
    // NOTE(hbrodin): The &* is because I wasn't able to construct the span from
    // an iterator in this compiler version. Only a pointer was accepted.
    return WriteCtx{
        span_t(&*std::exchange(write_it_, new_write_it), allocation_size),
        std::move(l)};
  }

  // Returns the offset of it, computed from beginning of section
  // NOTE(hbrodin): Error exit if it is not within the allocated part of the
  // section
  size_t offset(span_t::iterator it) const {
    if (it < mem_.begin() || it >= mem_.end()) {
      error_exit(
          "Can't compute offset of iterator that is not within section.");
    }
    return std::distance(mem_.begin(), it);
  }

  // Returns the offset of p, computed from beginning of section
  // NOTE(hbrodin): Error exit if it is not within the allocated part of the
  // section
  size_t offset(uint8_t const *p) const {
    if (p < &*mem_.begin() || &*mem_.end() <= p)
      error_exit("Can't compute offset of pointer that is not within section.");
    return p - &*mem_.begin();
  }

  // The full range of memory assigned to this section
  span_t mem_;

private:
  // Current write position in mem_
  span_t::iterator write_it_;

  // Want to be able to call const-methods such as size() and still lock to
  // ensure any pending write is protected.
  mutable std::mutex m_;
};

// Convenience base for allocation of fixed size entries
template <typename T> struct FixedSizeAlloc : SectionBase {
  static constexpr size_t align_of = alignof(T);

  FixedSizeAlloc(SectionBase::span_t rng) : SectionBase{rng} {
    if (reinterpret_cast<uintptr_t>(&*rng.begin()) % align_of != 0)
      error_exit("FixedSizeAlloc requires memory to be aligned on align_of.");

    if (rng.size() % entry_size() != 0) {
      error_exit(
          "FixedSizeAlloc requires memory to be a multiple of entry_size().");
    }
  }

  constexpr size_t entry_size() const {
    return sizeof(T);
  } // TODO(hbrodin): Handle alignment/padding issues in a good way

  // Helper type to ensure object construction can be done while holding a lock
  // to ensure exclusive access.
  struct ConstructCtx {
    // WriteCtx from SectionBase provides accesss to the memory range and is
    // responsible for locking the section.
    SectionBase::WriteCtx ctx;

    // Reference to the newly constructed object.
    T &t;
  };

  // Construct an object of type T in the section assigned memory.
  // If successfull a ConstructCtx is returned. Callers have exclusive
  // access to the section for the life time of the ConstructCtx.
  // N.b. count()/size() competes for the same lock.
  template <typename... Args>
  std::optional<ConstructCtx> construct(Args &&...args) {
    return map(SectionBase::write(entry_size()), [&](auto &ctx) {
      return ConstructCtx{.ctx = std::move(ctx),
                          .t = *new (&*ctx.mem.begin())
                                   T{std::forward<Args>(args)...}};
    });
  }

  // Constructs n instances as a sequence of T.
  // Each T is constructed by successive invocation of generator.
  template <typename F>
  std::optional<std::span<T const>> construct_range(
      size_t n,
      F &&generator) /* TODO(hbrodin): require(generator(uint8_t *)*/ {
    // TODO(hbrodin): Check n > 0
    auto mem_size = entry_size() * n;
    return map(SectionBase::write(mem_size),
               [&](auto &ctx) -> std::span<T const> {
                 for (auto it = ctx.mem.begin(); it != ctx.mem.end();
                      it += entry_size()) {
                   generator(&*it);
                 }
                 return {reinterpret_cast<T const *>(&*ctx.mem.begin()), n};
               });
  }

  // Returns the index of an allocated entry.
  size_t index(T const &e) const {
    // TODO(hbrodin): Add assertions
    return offset(reinterpret_cast<uint8_t const *>(&e)) / entry_size();
  }

  // Returns the number of constructed items
  size_t count() const { return size() / entry_size(); }

  // To allow iteration of entries
  // Does not lock the section to get count. Beginning is known.
  // Correct usage requires end() to be invoked to ensure begin() != end().
  T const *begin() const { return reinterpret_cast<T const *>(&*mem_.begin()); }

  // End of iteration.
  // Will lock the section to ensure that an accurate count can be retrieved.
  // Also, any change made prior to acquiring lock will be visible. This ensures
  // structures have correct content.
  // N.b. the section is not locked during iteration. Only data that was visible
  // at the time of invoking end() will be accessible.
  T const *end() const { return begin() + count(); }
};

} // namespace taintdag
#endif
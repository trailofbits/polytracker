/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <atomic>
#include <climits>
#include <span>

#include "taintdag/error.hpp"
#include "taintdag/taint.hpp"
#include "taintdag/util.hpp"

namespace taintdag {

using BitCount = size_t;
using BitIndex = size_t;

// Atomic bitset. Can set single values or ranges of bits and query if
// individual bits are set.
template <uint8_t Tag, BitCount BitCapacity, typename BucketType = uint64_t>
class BitmapSectionBase {
public:
  using bucket_t = BucketType;
  using span_t = std::span<uint8_t>;
  using atomic_t = std::atomic<BucketType>;

  static_assert(sizeof(atomic_t) == sizeof(bucket_t),
                "Atomic size differs from BucketType. Implementation does not "
                "support this situation.");

  static_assert(BitCapacity > 0, "BitCapacity must be greater than zero");

  // Assumes bits per byte is 8
  static_assert(CHAR_BIT == 8,
                "Implementation is currently only tested with 8-bit chars");

  // Represents how many bits are represented per bucket.
  static constexpr size_t bits_per_bucket = sizeof(bucket_t) * 8;

  // How many buckets of type T are needed
  static constexpr size_t bucket_count =
      (BitCapacity + bits_per_bucket - 1) / bits_per_bucket;

  // Properties required to fulfill the Section concept.
  static constexpr size_t allocation_size{sizeof(atomic_t[bucket_count])};
  static constexpr size_t align_of{alignof(atomic_t)};
  static constexpr uint8_t tag{Tag};

  // NOTE: This class does not initialize the mapped_range to any specific
  // value. If the intention is to have every bit not set originally, the
  // mapped_range memory needs to be zero upon construction. This behavior is by
  // design as the intention is to not touch any memory not explicitly set. As
  // the memory backing the atomic type (mem_), is mmap'ed from the TDAG-file,
  // as few written pages as possible are desired to keep the amount pages
  // needing to be flushed to disk (file) to a minimum.
  BitmapSectionBase(span_t mapped_range) : mem_{mapped_range} {
    if (mapped_range.size() % align_of != 0)
      error_exit("BitmapSectionBase, allocated memory size is not a multiple "
                 "of the bucket type.");

    if (mapped_range.size() < allocation_size)
      error_exit("BitmapSectionBase, allocated memory is too small.");

    // Construct the atomic values (shouldn't initialize to any specific value).
    new (&*mem_.begin()) atomic_t[bucket_count];
  }

  // Part of the Section-concept. Returns how many bytes are actually used in
  // the available memory (sequentially, starting from offset 0).
  size_t size() const {
    return buckets_used_.load(std::memory_order_relaxed) * sizeof(bucket_t);
  }

  // Sets the bit designated by bitno, returns if it was previously set.
  // bitno >= bit_capactity will cause error_exit.
  bool set(BitIndex bitno) {
    if (bitno >= BitCapacity)
      error_exit("Trying to set bit beyond capacity.");
    const BucketIndex bidx = bucket_index(bitno);
    const BucketType m = mask(bitno);
    auto &b = bucket(bidx);

    // NOTE(hbrodin): There is a slight chance for inconsistency here. If
    // the size() method is invoked (which should really only happen on
    // shutdown), there could be more bits set than reported bucket use.
    // TODO(hbrodin): Consider if this is a problem in reality and if so rewrite
    // to use a lock or similar.
    auto ret = set_bits(b, m);
    update_buckets_used(bidx);
    return ret;
  }

  // Sets n bits starting at bit_begin.
  // Essentially the same as calling set (above) in a loop, but optimized for
  // setting bits in a sequence.
  void set_range(BitIndex bit_begin, BitCount n) {
    if (n == 0)
      return;
    if (bit_begin >= BitCapacity)
      error_exit("Trying to set bit beyond capacity.");
    if (bit_begin + n > BitCapacity)
      error_exit("Trying to set bit beyond capacity.");

    auto current_bucket = bucket_index(bit_begin);
    const auto bucket_bit_start = bit_begin % bits_per_bucket;

    // If bit_begin is not aligned to the bucket size, this will
    // set all bits up to the next bucket_size bits.
    if (bucket_bit_start != 0) {
      const auto bit_end = std::min(bucket_bit_start + n, bits_per_bucket);

      const auto mask =
          (all_bits_set << bucket_bit_start) & // set bits from bucket_bit_start
                                               // to bits_per_bucket
          (all_bits_set >>
           (bits_per_bucket -
            bit_end)); // clear bits from bit_end to bits_per_bucket

      set_bits(bucket(current_bucket), mask);
      n -= bit_end - bucket_bit_start; // Reduce by the number of written bits
      ++current_bucket;
    }

    // It is now bucket aligned, set as many full buckets as possible
    // As this implementation only supports setting bits, a single store is
    // sufficient. The operation will set all bits of the buckets so there is no
    // need to take respect previous bits set.
    const auto n_full_buckets = n / bits_per_bucket;
    const auto end_full_buckets = current_bucket + n_full_buckets;
    for (; current_bucket < end_full_buckets; ++current_bucket) {
      // Fill each bucket with bits
      bucket(current_bucket).store(all_bits_set, std::memory_order_relaxed);
    }
    n -= n_full_buckets * bits_per_bucket;

    // If there are any remaining bits after the full buckets have been written
    // set those bits in the final (partial) bucket.
    if (n > 0) {
      const auto mask_post = all_bits_set >> (bits_per_bucket - n);
      set_bits(bucket(current_bucket), mask_post);
    }
    // NOTE(hbrodin): See the comment in set about potential inconsistency.
    update_buckets_used(current_bucket);
  }

  // Returns wheter the bit designated by bitno is set or not.
  // bitno >= bit_capactity will cause error_exit.
  bool is_set(BitIndex bitno) const {
    if (bitno >= BitCapacity)
      error_exit("Trying to check if bit beyond capacity is set.");
    return bucket_value(bucket_index(bitno)) & mask(bitno);
  }

private:
  // Helper type indicating index of a bucket, not a bit
  using BucketIndex = size_t;

  // When a bucket is completely empty it will have this value
  static constexpr BucketType no_bits_set{0u};

  // When a bucket is completely full it will have this value
  static constexpr BucketType all_bits_set{
      static_cast<BucketType>(~no_bits_set)};

  // Returns a mask that filters out only bitno from a bucket
  // TODO(hbrodin): Does it matter which bit as long as it is consistent? I.e.
  // is it important that bit 64 is adjacent to 63 in memory. If so, need to
  // handle endianess.
  inline BucketType mask(BitIndex bitno) const {
    size_t bitset = bitno % bits_per_bucket;
    return BucketType{1} << bitset;
  }

  // Returns the index of the bucket that holds the bit at index bitno
  inline BucketIndex bucket_index(BitIndex bitno) const {
    return bitno / bits_per_bucket;
  }

  // Returns an immutable reference to the bucket indexed by idx
  inline atomic_t &bucket(BucketIndex bucket_index) const {
    return reinterpret_cast<atomic_t *>(mem_.data())[bucket_index];
  }

  // Returns a mutable reference to the bucket indexed by idx
  inline atomic_t &bucket(BucketIndex bucket_index) {
    return reinterpret_cast<atomic_t *>(mem_.data())[bucket_index];
  }

  // Returns the value currently stored in the bucket indexed by idx
  inline auto bucket_value(BucketIndex bucket_index) const {
    return bucket(bucket_index).load(std::memory_order_relaxed);
  }

  // Will set the bits atomically in the bucket.
  // The function can handle concurrent updates to the same bucket.
  // Returns true if the bucket already had all requested bits set,
  // false if not.
  inline bool set_bits(atomic_t &bucket, bucket_t bits) {
    auto old = bucket.load(std::memory_order_relaxed);
    do {
      // Already set?
      if ((old & bits) == bits)
        return true;
    } while (!bucket.compare_exchange_weak(old, old | bits,
                                           std::memory_order_relaxed));
    return false;
  }

  // Will update the maximum number of buckets used based on what bucket index
  // (bidx) was just written. This will later be reflected in size where the
  // number of bytes used is returned.
  inline void update_buckets_used(BucketIndex bidx) {
    auto new_max = bidx + 1;
    auto old_max = buckets_used_.load(std::memory_order_relaxed);
    do {
      if (old_max > new_max)
        return;
    } while (!buckets_used_.compare_exchange_weak(old_max, new_max,
                                                  std::memory_order_relaxed));
  }

  // Counter responsible for keeping track of how many buckets are being used.
  // Will be reflected in the size()-function.
  std::atomic<BucketIndex> buckets_used_{0};

  // Backing memory for the bitset. Typically from a section in the memory
  // mapped TDAG-file.
  span_t mem_;
};

} // namespace taintdag
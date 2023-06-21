#include "oram.h"

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include "../../../utils/crypto.h"

namespace dyno::dynamic_stepping_path_oram {

ORam::ORam(int starting_size_power_of_two, size_t val_len)
    : capacity_(1UL << starting_size_power_of_two),
      val_len_(val_len),
      size_(1UL << (starting_size_power_of_two)) {
  auto base_cap = capacity_ >> 1;
  for (int i = 0; i < 2; ++i)
    sub_orams_[i] = std::make_unique<PORam>(base_cap << i, val_len, true);
}

bool IsPowerOfTwo(size_t x) {
  return !(x & (x - 1));
}

void ORam::Grow(crypto::Key enc_key) {
  if (capacity_ == 0) {
    sub_orams_[1] = std::make_unique<PORam>(1, val_len_, true);
    ++capacity_;
    return;
  }

  if (IsPowerOfTwo(capacity_)) {
    assert(sub_orams_[1] != nullptr);
    sub_orams_[0] = std::move(sub_orams_[1]);
    sub_orams_[1] = std::make_unique<PORam>(2 * capacity_, val_len_, true);
  }

  assert(sub_orams_[0] != nullptr && sub_orams_[1] != nullptr);
  Key move_idx = (capacity_ % sub_orams_[0]->Capacity()) + 1;
  auto start_accesses = SubORamsMemoryAccessCountSum();
  auto start_bytes = SubORamsMemoryBytesMovedTotalSum();
  auto move_bl = sub_orams_[0]->ReadAndRemove(0, move_idx, enc_key);
  if (!move_bl.meta_.key_) {
    sub_orams_[1]->DummyAccess(enc_key);
  } else {
    sub_orams_[1]->Insert(std::move(move_bl), enc_key);
  }
  memory_access_count_ += SubORamsMemoryAccessCountSum() - start_accesses;
  memory_bytes_moved_total_ += SubORamsMemoryBytesMovedTotalSum() - start_bytes;
  ++capacity_;
}

// Returns 0-value of Val if nothing found.
Block ORam::ReadAndRemove(Key k, crypto::Key enc_key) {
  assert(1 <= k && k <= capacity_);
  Block res;
  auto idx = SubOramIndex(k);
  auto start_accesses = SubORamsMemoryAccessCountSum();
  auto start_bytes = SubORamsMemoryBytesMovedTotalSum();
  for (int i = 0; i < 2; ++i) {
    // Skip the first sub structure if 1. it's null (size==1) or it's known to
    // be empty (IsPowerOfTwo(capacity_)).
    if (i == 0 && (sub_orams_[i] == nullptr || IsPowerOfTwo(capacity_)))
      continue;

    if (i == idx) {
      auto bl = sub_orams_[i]->ReadAndRemove(0, k, enc_key);
      res = Block(std::move(bl));
    } else {
      sub_orams_[i]->DummyAccess(enc_key);
    }
  }
  if (res.key_)
    --size_;
  memory_access_count_ += SubORamsMemoryAccessCountSum() - start_accesses;
  memory_bytes_moved_total_ += SubORamsMemoryBytesMovedTotalSum() - start_bytes;
  return res;
}

// Returns 0-value of Val if nothing found.
Block ORam::Read(Key k, crypto::Key enc_key) {
  assert(1 <= k && k <= capacity_);
  Block res;
  auto idx = SubOramIndex(k);
  auto start_accesses = SubORamsMemoryAccessCountSum();
  auto start_bytes = SubORamsMemoryBytesMovedTotalSum();
  for (int i = 0; i < 2; ++i) {
    // Skip the first sub structure if 1. it's null (size==1) or it's known to
    // be empty (IsPowerOfTwo(capacity_)).
    if (i == 0 && (sub_orams_[i] == nullptr || IsPowerOfTwo(capacity_)))
      continue;

    if (i == idx) {
      auto bl = sub_orams_[i]->Read(0, k, enc_key);
      res = Block(std::move(bl));
    } else {
      sub_orams_[i]->DummyAccess(enc_key);
    }
  }
  memory_access_count_ += SubORamsMemoryAccessCountSum() - start_accesses;
  memory_bytes_moved_total_ += SubORamsMemoryBytesMovedTotalSum() - start_bytes;
  return res;
}

void ORam::Insert(Key k, Val v, crypto::Key enc_key) {
  assert(1 <= k && k <= capacity_);
  auto idx = SubOramIndex(k);
  auto start_accesses = SubORamsMemoryAccessCountSum();
  auto start_bytes = SubORamsMemoryBytesMovedTotalSum();
  for (int i = 0; i < 2; ++i) {
    if (sub_orams_[i] == nullptr)
      continue;

    if (i == idx) {
      sub_orams_[i]->Insert({0, k, std::move(v)}, enc_key);
    } else {
      sub_orams_[i]->DummyAccess(enc_key);
    }
  }
  ++size_;
  memory_access_count_ += SubORamsMemoryAccessCountSum() - start_accesses;
  memory_bytes_moved_total_ += SubORamsMemoryBytesMovedTotalSum() - start_bytes;
}

uint8_t ORam::SubOramIndex(Key k) {
  assert(1 <= k && k <= capacity_);
  if (capacity_ == 1)
    return 1;
  if (k > sub_orams_[0]->Capacity() ||
      k <= (capacity_ - sub_orams_[0]->Capacity()))
    return 1;
  return 0;
}

uint64_t ORam::SubORamsMemoryAccessCountSum() {
  uint64_t res = 0;
  for (auto &so : sub_orams_) {
    if (so != nullptr) {
      res += so->MemoryAccessCount();
    }
  }
  return res;
}

uint64_t ORam::SubORamsMemoryBytesMovedTotalSum() {
  uint64_t res = 0;
  for (auto &so : sub_orams_) {
    if (so != nullptr) {
      res += so->MemoryBytesMovedTotal();
    }
  }
  return res;
}

} // dyno::dynamic_stepping_path_oram

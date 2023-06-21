#include "omap.h"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "../../../static/omap/path_avl/omap.h"
#include "../../../utils/crypto.h"

namespace dyno::dynamic_stepping_path_omap {

namespace {
bool IsPowerOfTwo(size_t x) {
  return !(x & (x - 1));
}
} // namespace

OMap::OMap(int starting_size_power_of_two, size_t val_len,
           std::string path, uint8_t max_levels_in_mem)
    : capacity_(1UL << starting_size_power_of_two),
      val_len_(val_len),
      size_(1UL << starting_size_power_of_two),
      store_path_(std::move(path)),
      max_mem_level_(max_levels_in_mem) {
  auto base_cap = capacity_ >> 1;
  if (capacity_)
    for (int i = 0; i < 2; ++i)
      sub_omaps_[i] = std::make_unique<POMap>(base_cap << i, val_len_,
                                              store_path_, max_mem_level_);
}

void OMap::Grow(crypto::Key enc_key) {
  if (capacity_ == 0) {
    sub_omaps_[1] = std::make_unique<POMap>(1, val_len_,
                                            store_path_, max_mem_level_);
    ++capacity_;
    return;
  }

  if (IsPowerOfTwo(capacity_)) {
    assert(sub_omaps_[1] != nullptr);
    sub_omaps_[0] = std::move(sub_omaps_[1]);
    sub_omaps_[1] = std::make_unique<POMap>(2 * capacity_, val_len_,
                                            store_path_, max_mem_level_);
  }

  assert(sub_omaps_[0] != nullptr && sub_omaps_[1] != nullptr);
  auto start_accesses = SubOMapsMemoryAccessCountSum();
  auto start_bytes = SubOMapsMemoryBytesMovedTotalSum();
  auto move_kv = sub_omaps_[0]->TakeOne(enc_key);
  if (!move_kv.key_ && !move_kv.val_) {
    sub_omaps_[1]->Read(0, enc_key); // Dummy
  } else {
    sub_omaps_[1]->Insert(move_kv.key_, std::move(move_kv.val_), enc_key);
  }
  ++capacity_;
  memory_access_count_ += SubOMapsMemoryAccessCountSum() - start_accesses;
  memory_bytes_moved_total_ += SubOMapsMemoryBytesMovedTotalSum() - start_bytes;
}

void OMap::Shrink(crypto::Key enc_key) {
  if (capacity_ == 0)
    return;

  assert(capacity_ > size_);

  if (capacity_ == 1) {
    for (auto &so : sub_omaps_) {
      so.reset();
    }
    capacity_ = 0;
    return;
  }

  assert(sub_omaps_[0] != nullptr && sub_omaps_[1] != nullptr);
  auto start_accesses = SubOMapsMemoryAccessCountSum();
  auto start_bytes = SubOMapsMemoryBytesMovedTotalSum();
  for (int i = 0; i < 2; ++i) {
    KeyValPair move_kv(0, nullptr);
    if (sub_omaps_[0]->Size() < sub_omaps_[0]->Capacity()) {
      move_kv = sub_omaps_[1]->TakeOne(enc_key);
    } else {
      sub_omaps_[1]->Read(0, enc_key); // Dummy
    }
    if (!move_kv.key_ && !move_kv.val_) {
      sub_omaps_[0]->Read(0, enc_key); // Dummy
    } else {
      sub_omaps_[0]->Insert(move_kv.key_, std::move(move_kv.val_), enc_key);
    }
  }
  --capacity_;
  memory_access_count_ += SubOMapsMemoryAccessCountSum() - start_accesses;
  memory_bytes_moved_total_ += SubOMapsMemoryBytesMovedTotalSum() - start_bytes;

  if (IsPowerOfTwo(capacity_)) {
    sub_omaps_[1] = std::move(sub_omaps_[0]);
    size_t smaller_size = capacity_ / 2;
    if (smaller_size) {
      sub_omaps_[0] =
          std::make_unique<POMap>(capacity_ / 2, val_len_,
                                  store_path_, max_mem_level_);
    } else {
      sub_omaps_[0].reset();
    }
  }
}

void OMap::Insert(Key key, Val val, crypto::Key enc_key) {
  assert(size_ < capacity_);
  auto start_accesses = SubOMapsMemoryAccessCountSum();
  auto start_bytes = SubOMapsMemoryBytesMovedTotalSum();
  size_t pre_size = TotalSizeOfSubOmaps();
  if (sub_omaps_[0] != nullptr) // Corner case: capacity = 1
    sub_omaps_[0]->ReadAndRemove(key, enc_key);
  sub_omaps_[1]->Insert(key, std::move(val), enc_key);
  if (TotalSizeOfSubOmaps() > pre_size)
    ++size_; // Else it was a pre-existing key
  memory_access_count_ += SubOMapsMemoryAccessCountSum() - start_accesses;
  memory_bytes_moved_total_ += SubOMapsMemoryBytesMovedTotalSum() - start_bytes;
}

Val OMap::Read(Key key, crypto::Key enc_key) {
  Val res;
  auto start_accesses = SubOMapsMemoryAccessCountSum();
  auto start_bytes = SubOMapsMemoryBytesMovedTotalSum();
  for (int i = 0; i < 2; ++i) {
    // Skip the first sub structure if 1. it's null (size==1) or it's known to
    // be empty (IsPowerOfTwo(capacity_)).
    if (i == 0 && (sub_omaps_[i] == nullptr || IsPowerOfTwo(capacity_)))
      continue;
    auto so_val = sub_omaps_[i]->Read(key, enc_key);
    if (so_val)
      res = std::move(so_val); // ≤1 so_res is valid.
  }
  memory_access_count_ += SubOMapsMemoryAccessCountSum() - start_accesses;
  memory_bytes_moved_total_ += SubOMapsMemoryBytesMovedTotalSum() - start_bytes;
  return res;
}

Val OMap::ReadAndRemove(Key key, crypto::Key enc_key) {
  size_t pre_size = TotalSizeOfSubOmaps();
  Val res;
  auto start_accesses = SubOMapsMemoryAccessCountSum();
  auto start_bytes = SubOMapsMemoryBytesMovedTotalSum();
  for (int i = 0; i < 2; ++i) {
    // Skip the first sub structure if 1. it's null (size==1) or it's known to
    // be empty (IsPowerOfTwo(capacity_)).
    if (i == 0 && (sub_omaps_[i] == nullptr || IsPowerOfTwo(capacity_)))
      continue;
    auto so_val = sub_omaps_[i]->ReadAndRemove(key, enc_key);
    if (so_val)
      res = std::move(so_val); // ≤1 so_res is valid.
  }
  if (TotalSizeOfSubOmaps() < pre_size)
    --size_;
  memory_access_count_ += SubOMapsMemoryAccessCountSum() - start_accesses;
  memory_bytes_moved_total_ += SubOMapsMemoryBytesMovedTotalSum() - start_bytes;
  return res;
}

size_t OMap::TotalSizeOfSubOmaps() const {
  size_t res = 0;
  for (auto &so : sub_omaps_)
    if (so != nullptr)
      res += so->Size();
  return res;
}

size_t OMap::Size() const {
  assert(size_ == TotalSizeOfSubOmaps());
  return size_;
}

uint64_t OMap::SubOMapsMemoryAccessCountSum() const {
  unsigned long long res = 0;
  for (auto &so : sub_omaps_) {
    if (so != nullptr) {
      res += so->MemoryAccessCount();
    }
  }
  return res;
}

uint64_t OMap::SubOMapsMemoryBytesMovedTotalSum() const {
  unsigned long long res = 0;
  for (auto &so : sub_omaps_) {
    if (so != nullptr) {
      res += so->MemoryBytesMovedTotal();
    }
  }
  return res;
}

bool OMap::IsOnDisk() const {
  bool res = false;
  for (auto &so : sub_omaps_)
    res |= so->IsOnDisk();
  return res;
}
} // dyno::dynamic_stepping_path_omap

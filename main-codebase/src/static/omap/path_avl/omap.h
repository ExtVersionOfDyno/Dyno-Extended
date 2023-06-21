#ifndef DYNO_STATIC_OMAP_PATH_AVL_H
#define DYNO_STATIC_OMAP_PATH_AVL_H

#include <cstdint>
#include <cstddef>
#include <map>
#include <string>

#include "../../../utils/crypto.h"
#include "../../oram/path/oram.h"

namespace dyno::static_path_omap {

using Key = uint32_t;
using Val = std::unique_ptr<uint8_t[]>;

using ORKey = static_path_oram::Key;
using ORPos = static_path_oram::Pos;
using ORVal = static_path_oram::Val;
using PathORam = static_path_oram::ORam;

class KeyValPair {
 public:
  Key key_;
  Val val_;

  KeyValPair() = default;
  KeyValPair(Key k, Val v) : key_(k), val_(std::move(v)) {}
};

class BlockPointer {
 public:
  ORKey key_;
  ORPos pos_;

  BlockPointer() = default;
  BlockPointer(ORKey k, ORPos p) : key_(k), pos_(p) {}
};

class BlockMetadata {
 public:
  Key key_ = 0;
  BlockPointer l_{0, 0}, r_{0, 0};
  uint8_t height_ = 0;

  BlockMetadata() = default;
  BlockMetadata(Key k, uint32_t h) : key_(k), height_(h) {}
  BlockMetadata(Key k, BlockPointer l, BlockPointer r, uint32_t h)
      : key_(k), l_(l), r_(r), height_(h) {}
};

class Block {
 public:
  BlockMetadata meta_;
  Val val_;

  Block() = default;
  Block(Key k, Val v, uint32_t h) : meta_(k, h), val_(std::move(v)) {}
  Block(Key k, Val v, BlockPointer l, BlockPointer r, uint32_t h)
      : meta_(k, l, r, h), val_(std::move(v)) {}
  Block(uint8_t *data, size_t val_len);

  ORVal ToBytes(size_t val_len);
};

static size_t BlockSize(size_t val_len) {
  return sizeof(BlockMetadata) + val_len;
}

class OMap {
 public:
  // PosixSingleFile -- On file store error reverts to RAM store.
  OMap(size_t n, size_t val_len, const std::string &file_path = "",
       uint8_t max_levels_in_mem = 0);
  void Insert(Key k, Val v, crypto::Key enc_key);
  Val Read(Key k, crypto::Key enc_Key);
  Val ReadAndRemove(Key k, crypto::Key enc_Key);
  KeyValPair TakeOne(crypto::Key enc_key);
  void FillWithDummies(crypto::Key enc_key);
  [[nodiscard]] size_t Capacity() const { return capacity_; }
  [[nodiscard]] size_t Size() const { return size_; }
  [[nodiscard]] uint64_t MemoryAccessCount() const { return oram_.MemoryAccessCount(); }
  [[nodiscard]] uint64_t MemoryBytesMovedTotal() const { return oram_.MemoryBytesMovedTotal(); }
  [[nodiscard]] bool IsOnDisk() const { return oram_.IsOnDisk(); }

 private:
  const size_t capacity_;
  const size_t val_len_;
  const uint32_t max_depth_;
  const uint32_t pad_val_;
  size_t size_ = 0;
  PathORam oram_;
  BlockPointer root_ = BlockPointer(0, 0); // Can and will change.
  uint32_t accesses_before_finalize_ = 0;
  std::map<ORKey, Block> cache_;
  Val delete_res_;
  bool delete_successful_ = false;

  BlockPointer Insert(Key k, Val &v, BlockPointer root, crypto::Key enc_key);
  BlockPointer Delete(Key k, BlockPointer root, crypto::Key enc_key);
  Block *Fetch(BlockPointer bp, crypto::Key enc_key);
  BlockPointer Balance(BlockPointer root, crypto::Key enc_key);
  int8_t BalanceFactor(BlockPointer bp, crypto::Key enc_key);
  uint8_t GetHeight(BlockPointer bp, crypto::Key enc_key);
  BlockPointer RotateLeft(BlockPointer root, crypto::Key enc_key);
  BlockPointer RotateRight(BlockPointer root, crypto::Key enc_key);
  void Finalize(crypto::Key enc_key);
  BlockPointer Find(Key key, BlockPointer root, crypto::Key enc_key);
};
} // namespace dyno::static_path_omap

#endif //DYNO_STATIC_OMAP_PATH_AVL_H

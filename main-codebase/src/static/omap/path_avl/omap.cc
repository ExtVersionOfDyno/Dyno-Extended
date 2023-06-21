#include "omap.h"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstddef>
#include <cmath>
#include <map>
#include <string>

#include "../../../utils/bytes.h"
#include "../../../utils/crypto.h"
#include "../../oram/path/oram.h"

#define max(a, b) ((a)>(b)?(a):(b))

namespace dyno::static_path_omap {

Block::Block(uint8_t *data, size_t val_len) {
  if (!data) return;
  bytes::FromBytes(data, meta_);
  val_ = std::make_unique<uint8_t[]>(val_len);
  std::copy_n(data + sizeof(BlockMetadata), val_len, val_.get());
}

ORVal Block::ToBytes(size_t val_len) {
  ORVal res = std::make_unique<uint8_t[]>(BlockSize(val_len));
  const auto meta_f = reinterpret_cast<const uint8_t *> (std::addressof(meta_));
  std::copy_n(meta_f, sizeof(BlockMetadata), res.get());
  if (val_)
    std::copy_n(val_.get(), val_len, res.get() + sizeof(BlockMetadata));
  return std::move(res);
}

OMap::OMap(size_t n, size_t val_len, const std::string &path,
           uint8_t max_levels_in_mem)
    : capacity_(n),
      val_len_(val_len),
      oram_(n, BlockSize(val_len), path, max_levels_in_mem, false, true),
      max_depth_(ceil(1.44 * log2(n))),
      pad_val_(ceil(1.44 * 3.0 * log2(n))) {}

void OMap::Insert(Key k, Val v, crypto::Key enc_key) {
  auto replacement = Insert(k, v, root_, enc_key);
  root_ = replacement;
  Finalize(enc_key);
}

Val OMap::ReadAndRemove(Key k, crypto::Key enc_Key) {
  auto replacement = Delete(k, root_, enc_Key);
  root_ = replacement;
  Val res;
  if (delete_successful_) {
    --size_;
    res = std::move(delete_res_);
    delete_successful_ = false;
  }
  Finalize(enc_Key);
  return std::move(res);
}

Val OMap::Read(Key k, crypto::Key enc_Key) {
  BlockPointer bp = Find(k, root_, enc_Key);
  Val res;
  if (bp.key_) { // Found
    res = std::make_unique<uint8_t[]>(val_len_);
    std::copy_n(cache_[bp.key_].val_.get(), val_len_, res.get());
  }
  Finalize(enc_Key);
  return std::move(res);
}

BlockPointer OMap::Insert(Key k, Val &v,
                          BlockPointer root_bp, crypto::Key enc_key) {
  if (!root_bp.key_) {
    root_bp.key_ = oram_.NextKey();
    cache_[root_bp.key_] = Block(k, std::move(v), 1);
    ++size_;
    return root_bp;
  }

  Block *current_block = Fetch(root_bp, enc_key);

  if (k == current_block->meta_.key_) {
    current_block->val_ = std::move(v);
    return root_bp;
  }

  // key != current_block->key_
  if (k < current_block->meta_.key_) {
    BlockPointer r = Insert(k, v, current_block->meta_.l_, enc_key);
    current_block->meta_.l_ = r;
  } else { // key > current_block->key_
    BlockPointer r = Insert(k, v, current_block->meta_.r_, enc_key);
    current_block->meta_.r_ = r;
  }

  // Adjust height
  current_block->meta_.height_ = 1 + max(
      GetHeight(current_block->meta_.l_, enc_key),
      GetHeight(current_block->meta_.r_, enc_key));

  // Finally, balance
  return Balance(root_bp, enc_key);
}

BlockPointer OMap::Delete(Key k, BlockPointer root_bp, crypto::Key enc_key) {
  if (!root_bp.key_) // Empty subtree
    return root_bp;

  Block *current_block = Fetch(root_bp, enc_key);

  // First, handle key != current_block->key_
  if (k < current_block->meta_.key_) {
    BlockPointer r = Delete(k, cache_[root_bp.key_].meta_.l_, enc_key);
    cache_[root_bp.key_].meta_.l_ = r;
    return Balance(root_bp, enc_key);
  } else if (k > current_block->meta_.key_) {
    BlockPointer r = Delete(k, cache_[root_bp.key_].meta_.r_, enc_key);
    cache_[root_bp.key_].meta_.r_ = r;
    return Balance(root_bp, enc_key);
  }

  // key == current_block->key_
  if (!delete_successful_) {
    delete_res_ = std::move(current_block->val_);
    delete_successful_ = true;
  } // Else the actual node had two children, and we're deleting the successor.

  auto lk = current_block->meta_.l_.key_;
  auto rk = current_block->meta_.r_.key_;

  // - No children
  if (!lk && !rk) {
    cache_.erase(root_bp.key_);
    oram_.AddFreedKey(root_bp.key_);
    return {0, 0};
  }

  // - One child
  if (lk && !rk) { // Has left child
    BlockPointer r = current_block->meta_.l_;
    cache_.erase(root_bp.key_);
    oram_.AddFreedKey(root_bp.key_);
    return r;
  }
  if (!lk && rk) { // Has right child
    BlockPointer r = current_block->meta_.r_;
    cache_.erase(root_bp.key_);
    oram_.AddFreedKey(root_bp.key_);
    return r;
  }

  // - Two children
  //   1. Find the successor
  unsigned int max_search_time = max_depth_;
  BlockPointer it = current_block->meta_.r_;
  Block *rpl;
  while (max_search_time--) {
    rpl = Fetch(it, enc_key);
    if (!rpl->meta_.l_.key_)
      break;
    it = rpl->meta_.l_;
  }

  //   2. Set current node's value to the successor's
  current_block->meta_.key_ = rpl->meta_.key_;
  current_block->val_ = std::move(rpl->val_);

  //   3. Delete the successor
  // This is done like this because the balancing of the replacement node may
  // cascade to its parents.
  current_block->meta_.r_ = Delete(rpl->meta_.key_,
                                   current_block->meta_.r_, enc_key);
  return Balance(root_bp, enc_key);
}

Block empty; // Hack! TODO: Fix
Block *OMap::Fetch(BlockPointer bp, crypto::Key enc_key) {
  if (!bp.key_) {
    empty = Block();
    return &empty;
  }

  if (cache_.find(bp.key_) != cache_.end()) { // Found in cache
    return &cache_[bp.key_];
  }

  assert(bp.pos_);
  ++accesses_before_finalize_;
  auto orb = oram_.ReadAndRemove(bp.pos_, bp.key_, enc_key);
  Block res(orb.val_.get(), val_len_);
  cache_[bp.key_] = std::move(res);
  return &cache_[bp.key_];
}

BlockPointer OMap::Balance(BlockPointer root_bp, crypto::Key enc_key) {
  auto bf = BalanceFactor(root_bp, enc_key);
  if (-1 <= bf && bf <= 1) // No rebalance necessary.
    return root_bp;

  Block &current_block = cache_[root_bp.key_];
  if (bf < -1) { //         Left-heavy
    auto l_bf = BalanceFactor(current_block.meta_.l_, enc_key);
    if (l_bf > 0) //        left-right
      current_block.meta_.l_ = RotateLeft(current_block.meta_.l_, enc_key);
    return RotateRight(root_bp, enc_key);
  }
  //                        Right-heavy
  auto r_bf = BalanceFactor(current_block.meta_.r_, enc_key);
  if (r_bf < 0) //          right-left
    current_block.meta_.r_ = RotateRight(current_block.meta_.r_, enc_key);
  return RotateLeft(root_bp, enc_key);
}

int8_t OMap::BalanceFactor(BlockPointer bp, crypto::Key enc_key) {
  auto current_node = Fetch(bp, enc_key);
  auto lh = GetHeight(current_node->meta_.l_, enc_key);
  auto rh = GetHeight(current_node->meta_.r_, enc_key);
  return rh - lh;
}

uint8_t OMap::GetHeight(BlockPointer bp, crypto::Key enc_key) {
  if (!bp.key_)
    return 0;
  return Fetch(bp, enc_key)->meta_.height_;
}

BlockPointer OMap::RotateLeft(BlockPointer root_bp, crypto::Key enc_key) {
  auto p = Fetch(root_bp, enc_key);
  auto l = Fetch(p->meta_.l_, enc_key);
  auto r = Fetch(p->meta_.r_, enc_key);
  auto rl = Fetch(r->meta_.l_, enc_key);
  auto rr = Fetch(r->meta_.r_, enc_key);

  auto res = p->meta_.r_;
  p->meta_.r_ = r->meta_.l_;
  p->meta_.height_ = 1 + max(l->meta_.height_, rl->meta_.height_);
  r->meta_.l_ = root_bp;
  r->meta_.height_ = 1 + max(p->meta_.height_, rr->meta_.height_);
  return res;
}

BlockPointer OMap::RotateRight(BlockPointer root_bp, crypto::Key enc_key) {
  auto p = Fetch(root_bp, enc_key);
  auto l = Fetch(p->meta_.l_, enc_key);
  auto r = Fetch(p->meta_.r_, enc_key);
  auto ll = Fetch(l->meta_.l_, enc_key);
  auto lr = Fetch(l->meta_.r_, enc_key);

  auto res = p->meta_.l_;
  p->meta_.l_ = l->meta_.r_;
  p->meta_.height_ = 1 + max(lr->meta_.height_, r->meta_.height_);
  l->meta_.r_ = root_bp;
  l->meta_.height_ = 1 + max(ll->meta_.height_, p->meta_.height_);
  return res;
}

void OMap::Finalize(crypto::Key enc_key) {
  // Pad reads
  for (unsigned int i = accesses_before_finalize_; i < pad_val_; ++i)
    oram_.DummyAccess(enc_key);
  accesses_before_finalize_ = 0;

  // Re-position and re-write all cached
  std::map<ORKey, ORPos> pos_map;
  for (auto &c : cache_) {
    ORKey ok = c.first;
    pos_map[ok] = oram_.GeneratePos();
  }

  if (pos_map.find(root_.key_) != pos_map.end())
    root_.pos_ = pos_map[root_.key_];

  for (auto &c : cache_) {
    ORKey ok = c.first;
    ORPos op = pos_map[ok];
    auto &b = c.second;
    if (pos_map.find(b.meta_.l_.key_) != pos_map.end())
      b.meta_.l_.pos_ = pos_map[b.meta_.l_.key_];
    if (pos_map.find(b.meta_.r_.key_) != pos_map.end())
      b.meta_.r_.pos_ = pos_map[b.meta_.r_.key_];
    auto ov = b.ToBytes(val_len_);
    b.val_.reset(); // release memory -- can do at the end too.
    oram_.Insert({op, ok, std::move(ov)}, enc_key);
  }
  auto writes_done = cache_.size();
  cache_.clear();

  // Pad writes
  while (writes_done++ < pad_val_)
    oram_.DummyAccess(enc_key);
}

BlockPointer OMap::Find(Key key, BlockPointer root_bp, crypto::Key enc_key) {
  if (!root_bp.key_) // Not found;
    return root_bp;
  Block *current_block = Fetch(root_bp, enc_key);
  if (key == current_block->meta_.key_)
    return root_bp;
  if (key < current_block->meta_.key_)
    return Find(key, current_block->meta_.l_, enc_key);
  return Find(key, current_block->meta_.r_, enc_key);
}

KeyValPair OMap::TakeOne(crypto::Key enc_key) {
  Block *root_block = Fetch(root_, enc_key);
  auto key = root_block->meta_.key_;
  auto val = ReadAndRemove(root_block->meta_.key_, enc_key);
  return {key, std::move(val)};
}

// Should only be called after allocation.
void OMap::FillWithDummies(crypto::Key enc_key) {
  oram_.FillWithDummies(enc_key);
}
} // namespace dyno::static_path_omap

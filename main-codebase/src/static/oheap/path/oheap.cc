#include "oheap.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cmath>
#include <memory>
#include <utility>
#include <vector>

#include "openssl/rand.h"

#include "../../../utils/bytes.h"
#include "../../../utils/crypto.h"
#include "../../../store/ram_store.h"
#include "../../../store/store.h"

namespace dyno::static_path_oheap {

Block::Block(uint8_t *data, size_t val_len) {
  bytes::FromBytes(data, meta_);
  val_ = std::make_unique<uint8_t[]>(val_len);
  std::copy_n(data + sizeof(BlockMetadata), val_len, val_.get());
}

Block::Block(const Block &b, const size_t val_len) : meta_(b.meta_) {
  if (!b.val_)
    return;
//  const auto v = new uint8_t[val_len];
//  std::copy_n(b.val_.get(), val_len, v);
//  val_ = std::unique_ptr<uint8_t[]>(v);
  val_ = std::make_unique<uint8_t[]>(val_len);
  std::copy_n(b.val_.get(), val_len, val_.get());
}

void Block::ToBytes(size_t val_len, uint8_t *out) {
  const auto meta_f = reinterpret_cast<const uint8_t *> (std::addressof(meta_));
  std::copy_n(meta_f, sizeof(BlockMetadata), out);
  if (val_)
    std::copy_n(val_.get(), val_len, out + sizeof(BlockMetadata));
}

Bucket::Bucket(uint8_t *data, size_t val_len) {
  bytes::FromBytes(data, meta_);
  size_t offset = sizeof(BucketMetadata);
  for (int i = 0; i < kBucketSize; ++i) {
    if (!(meta_.flags_ & kBlockValid[i]))
      break;
    blocks_[i] = Block(data + offset, val_len);
    offset += BlockSize(val_len);
  }
  min_block_ = Block(data + sizeof(BucketMetadata)
                         + (kBucketSize * BlockSize(val_len)), val_len);
}

std::unique_ptr<uint8_t[]> Bucket::ToBytes(size_t val_len) {
  auto res = std::make_unique<uint8_t[]>(BucketSize(val_len));
  ToBytes(res.get(), val_len);
  return std::move(res);
}

void Bucket::ToBytes(uint8_t *res, size_t val_len) {
  const auto meta_f = reinterpret_cast<const uint8_t *> (std::addressof(meta_));
  std::copy_n(meta_f, sizeof(BucketMetadata), res);
  size_t offset = sizeof(BucketMetadata);
  for (int i = 0; i < kBucketSize; ++i) {
    blocks_[i].ToBytes(val_len, res + offset);
    offset += BlockSize(val_len);
  }
  min_block_.ToBytes(val_len, res + offset);
}

OHeap::OHeap(size_t n, size_t val_len)
    : capacity_(n),
      val_len_(val_len),
      depth_(ceil(log2(n))),
      num_buckets_((2 * n) - 1),
      store_(std::make_unique<store::RamStore>(
          num_buckets_, EncryptedBucketSize(val_len))),
      bucket_buffer_(std::make_unique<uint8_t[]>(BucketSize(val_len))),
      enc_bucket_buffer_(std::make_unique<uint8_t[]>(
          EncryptedBucketSize(val_len))) {}

Block OHeap::FindMin(crypto::Key enc_key, bool pad) {
  ++memory_access_count_;
  memory_access_bytes_total_ += EncryptedBucketSize(val_len_);
  Block res(true);
  if (bucket_valid_[0]) {
    auto eb = store_->Read(0);
    auto plen = crypto::Decrypt(eb, EncryptedBucketSize(val_len_),
                                enc_key, bucket_buffer_.get());
    assert(plen == BucketSize(val_len_));
    auto bu = Bucket(bucket_buffer_.get(), val_len_);
    res = std::move(bu.min_block_);
    // No need to re-encrypt; the algorithm doesn't update the root here.
  }
  if (pad)
    DummyAccess(enc_key, false);
  return std::move(res);
}

Block OHeap::ExtractMin(crypto::Key enc_key) {
  Block min_block = FindMin(enc_key, false);
  if (!min_block.meta_.pos_) {
    DummyAccess(enc_key, false);
    return min_block;
  }

  Pos second_pos = GenerateSecondPos(min_block.meta_.pos_);
  ReadPath(min_block.meta_.pos_, enc_key,
           true, min_block.meta_.key_, &min_block.val_);
  UpdateMinAndEvict(min_block.meta_.pos_, enc_key);
  ReadPath(second_pos, enc_key);
  UpdateMinAndEvict(second_pos, enc_key);

  if (min_block.meta_.pos_)
    --size_;

  return min_block;
}

void OHeap::Insert(Key k, Val v, crypto::Key enc_key) {
  FindMin(enc_key, false); // To maintain obliviousness
  auto p = GeneratePos();
  auto evict_paths = GeneratePathPair();
  stash_.emplace_back(p, k, std::move(v));
  ReadPath(evict_paths.first, enc_key);
  UpdateMinAndEvict(evict_paths.first, enc_key);
  ReadPath(evict_paths.second, enc_key);
  UpdateMinAndEvict(evict_paths.second, enc_key);
  ++size_;
}

Pos OHeap::GeneratePos() const {
  Pos res;
  RAND_bytes(reinterpret_cast<unsigned char *>(&res), sizeof(Pos));
  res = (res % capacity_) + 1;
  return res;
}

void OHeap::DummyAccess(crypto::Key enc_key, bool with_find_min) {
  if (with_find_min)
    FindMin(enc_key, false);
  auto p2 = GeneratePathPair();
  ReadPath(p2.first, enc_key);
  UpdateMinAndEvict(p2.first, enc_key);
  ReadPath(p2.second, enc_key);
  UpdateMinAndEvict(p2.second, enc_key);
}

// Should only be called after allocation.
void OHeap::FillWithDummies(crypto::Key enc_key) {
  ++memory_access_count_;
  memory_access_bytes_total_ += num_buckets_ * EncryptedBucketSize(val_len_);
  Bucket empty;
  empty.ToBytes(bucket_buffer_.get(), val_len_);

  for (size_t i = 0; i < num_buckets_; ++i) {
    bool ok = crypto::Encrypt(bucket_buffer_.get(), BucketSize(val_len_),
                              enc_key, enc_bucket_buffer_.get());
    assert(ok);
    store_->Write(i, enc_bucket_buffer_.get());
  }
}

void OHeap::ReadPath(Pos p, crypto::Key enc_key,
                     bool erase_if_found, Key k, Val *v) {
  bool found_res = false; // Duplicates are allowed
  auto path = Path(p);
  ++memory_access_count_;
  memory_access_bytes_total_ += path.size() * EncryptedBucketSize(val_len_);
  for (auto it = path.rbegin(); it < path.rend(); ++it) {
    auto idx = *it;
    if (!bucket_valid_[idx]) {
      break;
    }
    auto eb = store_->Read(idx);
    auto plen = crypto::Decrypt(eb, EncryptedBucketSize(val_len_),
                                enc_key, bucket_buffer_.get());
    assert(plen == BucketSize(val_len_));
    auto bu = Bucket(bucket_buffer_.get(), val_len_);
    bucket_valid_[(2 * idx) + 1] = bu.meta_.flags_ & kLeftChildValid;
    bucket_valid_[(2 * idx) + 2] = bu.meta_.flags_ & kRightChildValid;
    for (int i = 0; i < kBucketSize; ++i) {
      if (!(bu.meta_.flags_ & kBlockValid[i])) {
        break;
      }
      if (!found_res && erase_if_found
          && p == bu.blocks_[i].meta_.pos_ && k == bu.blocks_[i].meta_.key_
          && std::equal(v->get(),
                        v->get() + val_len_,
                        bu.blocks_[i].val_.get())) {
        found_res = true;
      } else {
        stash_.push_back(std::move(bu.blocks_[i]));
      }
    }
    for (int i = 0; i < kBucketSize; ++i) bu.blocks_[i].val_.reset();
    bu.min_block_.val_.reset();
  }
}

void OHeap::UpdateMinAndEvict(Pos pos, crypto::Key enc_key) {
  auto path = Path(pos);
  ++memory_access_count_;
  memory_access_bytes_total_ += path.size() * EncryptedBucketSize(val_len_);
  std::vector<bool> deleted_from_stash(stash_.size());
  unsigned int level = depth_;
  Block children_min_block(true);
  for (unsigned int idx : path) {
    Bucket bu;
    int bucket_index = 0;
    for (int i = 0; i < stash_.size() && bucket_index < kBucketSize; i++) {
      if (deleted_from_stash[i])
        continue;
      if (PathAtLevel(stash_[i].meta_.pos_, level) == idx) {
        bu.blocks_[bucket_index] = std::move(stash_[i]);
        deleted_from_stash[i] = true;
        bu.meta_.flags_ |= kBlockValid[bucket_index];
        ++bucket_index;
      }
    }

    bucket_valid_[idx] = true;
    if (bucket_valid_[(2 * idx) + 1])
      bu.meta_.flags_ |= kLeftChildValid;
    if (bucket_valid_[(2 * idx) + 2])
      bu.meta_.flags_ |= kRightChildValid;

    // find min block;
    auto min_i = -1;
    auto min_k = children_min_block.meta_.key_;
    for (int i = 0; i < kBucketSize; ++i) {
      if (!(bu.meta_.flags_ & kBlockValid[i]))
        break;
      if ((min_i == -1 && !children_min_block.meta_.pos_)
          || bu.blocks_[i].meta_.key_ < min_k) {
        min_i = i;
        min_k = bu.blocks_[i].meta_.key_;
      }
    }

    // set min block
    if (min_i != -1) {
      bu.min_block_ = Block(bu.blocks_[min_i], val_len_);
    } else {
      bu.min_block_ = Block(children_min_block, val_len_);
    }

    // update children_min_block
    auto sibling_min_block = SiblingMin(idx, enc_key);
    if (sibling_min_block.meta_.pos_
        && (!bu.min_block_.meta_.pos_
            || (sibling_min_block.meta_.key_ < bu.min_block_.meta_.key_))) {
      children_min_block = std::move(sibling_min_block);
    } else if (min_i != -1) {
      children_min_block = Block(bu.min_block_, val_len_);
    }

    // encrypt
    bu.ToBytes(bucket_buffer_.get(), val_len_);
    bool ok = crypto::Encrypt(bucket_buffer_.get(), BucketSize(val_len_),
                              enc_key, enc_bucket_buffer_.get());
    assert(ok);
    store_->Write(idx, enc_bucket_buffer_.get());
    --level;
    sibling_min_block.val_.reset();
  }

  auto it = deleted_from_stash.begin();
  stash_.erase(
      std::remove_if(stash_.begin(), stash_.end(),
                     [&](Block &) { return *it++; }),
      stash_.end()
  );
  bucket_valid_.clear();
  bucket_valid_[0] = true;
}

Block OHeap::SiblingMin(unsigned int idx, crypto::Key enc_key) {
  unsigned int sibling_idx = idx % 2 ? idx + 1 : idx - 1;
  if (idx == 0 || !bucket_valid_[sibling_idx])
    return std::move(Block(true));

//  ++memory_access_count_; // No need, assuming all siblings are returned during path fetch.
  memory_access_bytes_total_ += EncryptedBucketSize(val_len_);

  auto eb = store_->Read(sibling_idx);
  auto plen = crypto::Decrypt(eb, EncryptedBucketSize(val_len_),
                              enc_key, bucket_buffer_.get());
  assert(plen == BucketSize(val_len_));
  auto bu = Bucket(bucket_buffer_.get(), val_len_);
  // No need to re-encrypt; the algorithm doesn't update the sibling.
  return std::move(bu.min_block_);
}

std::vector<unsigned int> OHeap::Path(Pos pos) const {
  assert(1 <= pos && pos <= capacity_);
  std::vector<unsigned int> res(depth_ + 1);
  unsigned int i = 0;
  unsigned int index = capacity_ - 1 + pos;
  while (index > 0) {
    res[i++] = index - 1; // index is 1-based but we need 0-based array indexes.
    index /= 2;
  }
  return res;
}

unsigned int OHeap::PathAtLevel(Pos pos, unsigned int level) const {
  return ((capacity_ - 1 + pos) / (1UL << (depth_ - level))) - 1;
}

std::pair<Pos, Pos> OHeap::GeneratePathPair() const {
  // 1 .. 2^{k-1}
  Pos pos1 = 1 + ((GeneratePos() - 1) >> 1);
  // 2^{k-1}+1 .. 2^k
  Pos pos2 = 1 + (((GeneratePos() - 1) >> 1) | (capacity_ >> 1));
  return std::make_pair(pos1, pos2);
}

Pos OHeap::GenerateSecondPos(Pos p) const {
  // 2^{k-1} if p >= 2^{k-1}; else 0
  Pos base = ((capacity_ >> 1) & (p - 1)) ^ (capacity_ >> 1);
  return (base | ((GeneratePos() - 1) >> 1)) + 1;
}
} // namespace dyno::static_path_oheap

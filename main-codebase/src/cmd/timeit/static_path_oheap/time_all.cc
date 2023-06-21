#include <chrono>
#include <iostream>
#include <memory>

#include "../../../static/oheap/path/oheap.h"
#include "../../../utils/crypto.h"
#include "../../../utils/measurements.h"

using namespace dyno::crypto;
using namespace dyno::measurement;
using namespace dyno::static_path_oheap;

const static std::string test_name = "soheap";

int main(int argc, char **argv) {
  Config conf(argc, argv);
  if (!conf.is_valid_)
    return 1;

  auto enc_key = GenerateKey();
  for (const auto &bs : conf.block_sizes_) {
    for (const auto &po2 : conf.po2s_) {
      Run total(test_name, po2, bs);
      size_t size = 1UL << po2;
      for (int r = 0; r < conf.num_runs_; ++r) {
        Measurement prev;
        Run run(test_name, po2, bs);
        auto oheap = std::make_unique<OHeap>(size, bs);
        run.alloc_.time_ = run.Elapsed();
        prev = {run.Elapsed(),
                oheap->MemoryAccessCount(),
                oheap->MemoryBytesMovedTotal()};

        oheap->Insert(1, {}, enc_key);
        run.insert_.time_ = run.Elapsed() - prev.time_;
        run.insert_.accesses_ = oheap->MemoryAccessCount() - prev.accesses_;
        run.insert_.bytes = oheap->MemoryBytesMovedTotal() - prev.bytes;
        prev = {run.Elapsed(),
                oheap->MemoryAccessCount(),
                oheap->MemoryBytesMovedTotal()};

        oheap->FindMin(enc_key);
        run.search_.time_ = run.Elapsed() - prev.time_;
        run.search_.accesses_ = oheap->MemoryAccessCount() - prev.accesses_;
        run.search_.bytes = oheap->MemoryBytesMovedTotal() - prev.bytes;
        prev = {run.Elapsed(),
                oheap->MemoryAccessCount(),
                oheap->MemoryBytesMovedTotal()};

        oheap->ExtractMin(enc_key);
        run.delete_.time_ = run.Elapsed() - prev.time_;
        run.delete_.accesses_ = oheap->MemoryAccessCount() - prev.accesses_;
        run.delete_.bytes = oheap->MemoryBytesMovedTotal() - prev.bytes;

        total = total + run;
        oheap.reset(); // cleanup
      }
      std::cout << (total / conf.num_runs_) << std::endl;
    }
  }
  return 0;
}

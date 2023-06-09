#ifndef RAMSTOREENCLAVEINTERFACE_H
#define RAMSTOREENCLAVEINTERFACE_H
#include "RAMStore.hpp"

static RAMStore* store = NULL;

void ocall_setup_ramStore(size_t num, int size) {
    if (size != -1) {
        store = new RAMStore(num, size, false);
    } else {
        store = new RAMStore(num, size, true);
    }
}

void ocall_nwrite_ramStore(size_t blockCount, long long* indexes, const char *blk, size_t len) {
    assert(len % blockCount == 0);
    size_t eachSize = len / blockCount;
    for (unsigned int i = 0; i < blockCount; i++) {
        block ciphertext(blk + (i * eachSize), blk + (i + 1) * eachSize);
        store->Write(indexes[i], ciphertext);
    }
}

size_t ocall_nread_ramStore(size_t blockCount, long long* indexes, char *blk, size_t len) {
    assert(len % blockCount == 0);
    size_t resLen = -1;
    for (unsigned int i = 0; i < blockCount; i++) {
        block ciphertext = store->Read(indexes[i]);
        resLen = ciphertext.size();
        std::memcpy(blk + i * resLen, ciphertext.data(), ciphertext.size());
    }
    return resLen;
}

int* testdata = NULL;

void ocall_test_memory_setup(int size) {
    testdata = new int[size];
    for (int i = 0; i < size; i++) {
        testdata[i] = i;
    }
}

void ocall_test_memory_read(int* indexes, int *data) {
    //    for (int i = 0; i < 1; i++) {
    //        int index = indexes[i];
    //        std::memcpy(&data[i], &testdata[index], sizeof(int));
    //    }
    for (int i = 0; i < 300; i++) {
        int index = indexes[i];
        std::memcpy(&data[i], &testdata[index], sizeof (int));
    }
}

void ocall_initialize_ramStore(long long begin, long long end, const char *blk, size_t len) {
    block ciphertext(blk, blk + len);
    for (long long i = begin; i < end; i++) {
        store->Write(i, ciphertext);
    }
}

void ocall_write_ramStore(long long index, const char *blk, size_t len) {
    block ciphertext(blk, blk + len);
    store->Write(index, ciphertext);
}
#endif /* RAMSTOREENCLAVEINTERFACE_H */


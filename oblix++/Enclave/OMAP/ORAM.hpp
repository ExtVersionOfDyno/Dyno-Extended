#ifndef ORAM_H
#define ORAM_H

#include "AES.hpp"
#include <random>
#include <vector>
#include <unordered_map>


#include "LocalRAMStore.hpp"
#include "Node.h"

using namespace std;

struct Block {
    bool isDummy;
    std::array<byte_t, sizeof (Node) > data;
};

struct Bucket {
    std::array<Block, Z> blocks;
    int num_blocks;
};

constexpr int Key = 16;
#define PERMANENT_STASH_SIZE 100
#define THRESHOLD 1

class Stash {
public:
    std::array<Node*, PERMANENT_STASH_SIZE> blocks;
    std::array<Bucket, PERMANENT_STASH_SIZE> pathBuckets;
    std::array<long long, PERMANENT_STASH_SIZE> pathIndexes;
    int pathSize;
};

class ORAM {
private:

    size_t blockSize;
    Stash stash;
    long long leaf;
    set<long long> leafList;
    unordered_map<long long, Bucket> virtualStorage;

    bytes<Key> key;
    size_t plaintext_size;
    long long bucketCount;
    size_t clen_size;
    bool batchWrite = false;
    long long maxOfRandom;
    long long maxHeightOfAVLTree;
    LocalRAMStore* localStore;
    bool useLocalRamStore = false;
    int storeBlockSize;


    long long GetNodeOnPath(long long leaf, int depth);

    void FetchPath(long long leaf, long long bid);
    void FetchBatchPath(long long leaf, long long bid);

    BucketBytes SerialiseBucket(Bucket bucket);
    Bucket DeserialiseBucket(BucketBytes buffer, long long bid, Node* insertedNode);
    void ConditionalInsert(Node* node, bool choice);

    void InitializeBuckets(long long strtindex, long long endindex, Bucket bucket);
    void EvictBuckets();
    void EvictBuckets(std::array<long long, 2000>* indexes, std::array<Bucket, 2000>* buckets, int counter);
    void SlowEvict();
    void BatchSlowEvict();
    void FastEvict();
    void BatchFastEvict();

    bool WasSerialised();
    Node* convertBlockToNode(std::array<byte_t, sizeof (Node) > b);
    std::array<byte_t, sizeof (Node) > convertNodeToBlock(Node* node);
    void WriteBucket(long long index, Bucket bucket);

public:
    ORAM(long long maxSize, bytes<Key> key, bool simulation);
    ORAM(long long maxSize, bytes<Key> oram_key, vector<Node*>* nodes);
    ~ORAM();
    double evicttime = 0;
    int num_writes = 0;

    int depth;

    unsigned long long RandomPath();
    unsigned long long Access(unsigned long long bid, unsigned long long pos, unsigned long long& content, bool batchAccess = false);
    void Evict(bool batchEvict = false);

    bool profile = false;

};

#endif

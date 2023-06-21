#include "ORAM.hpp"
#include <algorithm>
#include <iomanip>
#include <fstream>
#include <random>
#include <cmath>
#include <cassert>
#include <cstring>
#include <map>
#include <stdexcept>
#include "sgx_trts.h"
#include "ObliviousOperations.h"
#include "ORAMEnclaveInterface.h"
#include "Enclave_t.h"  /* print_string */
#include <algorithm>
#include <stdlib.h>
#include "Crypto.h"

ORAM::ORAM(long long maxSize, bytes<Key> oram_key, bool simulation)
: key(oram_key) {
    depth = (int) (ceil(log2(maxSize)) - 1) + 1;
    stash.pathSize = depth + 1;
    maxOfRandom = (long long) (pow(2, depth));
    Crypto::Setup();
    bucketCount = maxOfRandom * 2 - 1;
    printf("Number of leaves:%lld\n", maxOfRandom);
    printf("depth:%lld\n", depth);

    blockSize = sizeof (Node); // B  
    printf("block size is:%d\n", blockSize);
    size_t blockCount = (size_t) (Z * bucketCount);
    storeBlockSize = (size_t) (Crypto::GetCiphertextLength((int) (Z * (blockSize))));
    clen_size = Crypto::GetCiphertextLength((int) (blockSize) * Z);
    plaintext_size = (blockSize) * Z;
    if (!simulation) {
        ocall_setup_ramStore(blockCount, storeBlockSize);
    } else {
        ocall_setup_ramStore(depth, -1);
    }
    maxHeightOfAVLTree = (int) floor(log2(blockCount)) + 1;

    printf("Initializing ORAM Buckets\n");
    Bucket bucket;
    for (int z = 0; z < Z; z++) {
        bucket.blocks[z].data.fill(0);
        bucket.num_blocks = 0;
    }
    if (!simulation) {
        //        InitializeBuckets(0, bucketCount, bucket);
        long long i;
        for (i = 0; i < maxOfRandom - 1; i++) {
            if (i % 10000 == 0) {
                printf("%d/%d\n", i, bucketCount);
            }
            Bucket bucket;
            for (int z = 0; z < Z; z++) {
                bucket.blocks[z].data.fill(0);
                bucket.blocks[z].isDummy = true;
            }
            WriteBucket((int) i, bucket);
        }
        for (long long j = 0; i < bucketCount; i++, j++) {
            if (i % 10000 == 0) {
                printf("%d/%d\n", i, bucketCount);
            }
            Bucket bucket;

            Node* tmp = new Node();
            tmp->index = j;
            tmp->pos = j;
            bucket.blocks[0].data = convertNodeToBlock(tmp);
            bucket.blocks[0].isDummy = false;
            delete tmp;
            for (int z = 1; z < Z; z++) {
                bucket.blocks[z].data.fill(0);
                bucket.blocks[z].isDummy = true;
            }
            bucket.num_blocks = 1;
            WriteBucket((long long) i, bucket);
        }
    }

    for (auto i = 0; i < PERMANENT_STASH_SIZE; i++) {
        Node* dummy = new Node();
        dummy->index = 0;
        dummy->evictionNode = 0;
        dummy->pos = 0;
        dummy->isDummy = true;
        stash.blocks[i] = dummy;
    }
    printf("End of Initialization\n");
}

ORAM::~ORAM() {
    Crypto::Cleanup();
}

void ORAM::WriteBucket(long long index, Bucket bucket) {
    BucketBytes b = SerialiseBucket(bucket);
    EncBucketBytes ciphertext = Crypto::Encrypt(key, b, clen_size, plaintext_size, 1);
    ocall_write_ramStore(index, (const char*) ciphertext.data(), (size_t) ciphertext.size());
}

long long ORAM::GetNodeOnPath(long long leaf, int curDepth) {
    leaf += bucketCount / 2;
    for (int d = depth - 1; d >= 0; d--) {
        bool cond = !Node::CTeq(Node::CTcmp(d, curDepth), -1);
        leaf = Node::conditional_select((leaf + 1) / 2 - 1, leaf, cond);
    }
    return leaf;
}

BucketBytes ORAM::SerialiseBucket(Bucket bucket) {
    BucketBytes buffer;
    for (int z = 0; z < Z; z++) {
        Block b = bucket.blocks[z];
        std::copy(b.data.begin(), b.data.end(), buffer.begin()+(sizeof (Node)) * z);
    }
    return buffer;
}

void ORAM::ConditionalInsert(Node* node, bool choice) {
    bool found = false;
    bool inserted = !choice;
    for (Node* item : stash.blocks) {
        bool key_mathces = Node::CTeq(node->index, item->index);
        found = found || key_mathces;
        bool should_insert_now = choice && (key_mathces || !(inserted || (!item->isDummy)));
        Node::conditional_assign(item, node, should_insert_now);
        inserted = inserted || should_insert_now;
    }
}

Bucket ORAM::DeserialiseBucket(BucketBytes buffer, long long bid, Node* insertedNode) {
    Bucket bucket;
    int block_num = 0;
    std::array<byte_t, sizeof (Node) > zero;
    zero.fill(0);
    for (int z = 0; z < Z; z++) {
        Block &curBlock = bucket.blocks[z];
        std::copy(buffer.begin()+(sizeof (Node)) * z, buffer.begin()+(sizeof (Node))*(z + 1), curBlock.data.begin());
        Node* node = convertBlockToNode(curBlock.data);
        bool cond = Node::CTeq(node->index, (unsigned long long) 0);
        bool key_mathces = Node::CTeq(node->index, (unsigned long long) bid) && !cond;
        node->value = Node::conditional_select(node->value, (unsigned long long) 0, !cond);
        node->isDummy = Node::conditional_select(0, 1, !cond);
        curBlock.isDummy = node->isDummy;
        block_num = Node::conditional_select(block_num, block_num + 1, node->isDummy || key_mathces);
        Node::conditional_assign(insertedNode, node, key_mathces);

        Node::conditional_assign(curBlock.data, zero, key_mathces);
        curBlock.isDummy = Node::conditional_select(true, curBlock.isDummy, key_mathces);
        delete node;
    }
    bucket.num_blocks = block_num;
    return bucket;
}

void ORAM::InitializeBuckets(long long strtindex, long long endindex, Bucket bucket) {
    BucketBytes b = SerialiseBucket(bucket);
    EncBucketBytes ciphertext = Crypto::Encrypt(key, b, clen_size, plaintext_size, 1);
    ocall_initialize_ramStore(strtindex, endindex, (const char*) ciphertext.data(), (size_t) ciphertext.size());

}

void ORAM::EvictBuckets() {
    char* tmp = new char[stash.pathSize * storeBlockSize];
    Crypto::refreshIV(stash.pathSize);
    size_t cipherSize = 0;
    for (int i = 0; i < stash.pathSize; i++) {
        BucketBytes b = SerialiseBucket(stash.pathBuckets[i]);
        EncBucketBytes ciphertext = Crypto::Encrypt(key, b, clen_size, plaintext_size, i);
        std::copy(ciphertext.begin(), ciphertext.end(), tmp + i * ciphertext.size());
        cipherSize = ciphertext.size();
    }
    ocall_nwrite_ramStore(stash.pathSize, stash.pathIndexes.data(), (const char*) tmp, cipherSize * stash.pathSize);
    delete tmp;
}

void ORAM::EvictBuckets(std::array<long long, 2000>* indexes, std::array<Bucket, 2000>* buckets, int counter) {
    Crypto::refreshIV(counter);

    for (unsigned int j = 0; j <= counter / 10000; j++) {
        char* tmp = new char[10000 * storeBlockSize];
        size_t cipherSize = 0;
        for (int i = 0; i < min((int) (counter - j * 10000), 10000); i++) {
            BucketBytes b = SerialiseBucket((*buckets)[j * 10000 + i]);
            EncBucketBytes ciphertext = Crypto::Encrypt(key, b, clen_size, plaintext_size, i);
            std::copy(ciphertext.begin(), ciphertext.end(), tmp + i * ciphertext.size());
            cipherSize = ciphertext.size();
        }
        if (min((int) (counter - j * 10000), 10000) != 0) {

            ocall_nwrite_ramStore(min((int) (counter - j * 10000), 10000), indexes->data() + j * 10000, (const char*) tmp, cipherSize * min((int) (counter - j * 10000), 10000));
        }
        delete tmp;
    }

    virtualStorage.clear();
}
// Fetches blocks along a path, adding them to the stash

void ORAM::FetchPath(long long leaf, long long bid) {
    int maxNodesIndex = 0;
    long long node = leaf;

    node += bucketCount / 2;
    stash.pathIndexes[maxNodesIndex++] = node;

    for (int d = depth - 1; d >= 0; d--) {
        node = (node + 1) / 2 - 1;
        stash.pathIndexes[maxNodesIndex++] = node;
    }

    if (maxNodesIndex == 0) {
        return;
    }

    stash.pathSize = maxNodesIndex;
    size_t readSize;
    char* tmp = new char[maxNodesIndex * storeBlockSize];
    ocall_nread_ramStore(&readSize, maxNodesIndex, stash.pathIndexes.data(), tmp, maxNodesIndex * storeBlockSize);

    Node* insertNode = new Node();
    insertNode->index = 0;
    insertNode->isDummy = true;
    insertNode->pos = 0;
    insertNode->evictionNode = 0;

    for (unsigned int i = 0; i < maxNodesIndex; i++) {
        EncBucketBytes ciphertext;
        std::copy(tmp + i*readSize, tmp + (i + 1) * readSize, ciphertext.begin());
        BucketBytes buffer = Crypto::Decrypt(key, ciphertext, clen_size);
        Bucket bucket = DeserialiseBucket(buffer, bid, insertNode);
        stash.pathBuckets[i] = bucket;
    }

    ConditionalInsert(insertNode, !insertNode->isDummy);
    delete insertNode;
    delete tmp;

}

void ORAM::FetchBatchPath(long long leaf, long long bid) {
    vector<long long> nodesIndex;
    vector<long long> existingIndexes;
    long long node = leaf;

    node += bucketCount / 2;
    if (virtualStorage.count(node) == 0) {
        nodesIndex.push_back(node);
    } else {
        existingIndexes.push_back(node);
    }

    for (int d = depth - 1; d >= 0; d--) {
        node = (node + 1) / 2 - 1;
        if (virtualStorage.count(node) == 0) {
            nodesIndex.push_back(node);
        } else {
            existingIndexes.push_back(node);
        }
    }

    size_t readSize;
    Node* insertNode = new Node();
    insertNode->index = 0;
    insertNode->isDummy = true;
    insertNode->pos = 0;
    insertNode->evictionNode = 0;

    if (nodesIndex.size() > 0) {
        char* tmp = new char[nodesIndex.size() * storeBlockSize];
        ocall_nread_ramStore(&readSize, nodesIndex.size(), nodesIndex.data(), tmp, nodesIndex.size() * storeBlockSize);

        for (unsigned int i = 0; i < nodesIndex.size(); i++) {
            EncBucketBytes ciphertext;
            std::copy(tmp + i*readSize, tmp + (i + 1) * readSize, ciphertext.begin());
            BucketBytes buffer = Crypto::Decrypt(key, ciphertext, clen_size);
            Bucket bucket = DeserialiseBucket(buffer, bid, insertNode);
            virtualStorage[nodesIndex[i]] = bucket;
        }
        delete tmp;
    }

    std::array<byte_t, sizeof (Node) > zero;
    zero.fill(0);

    for (unsigned int i = 0; i < existingIndexes.size(); i++) {
        int block_num = 0;
        Bucket bucket = virtualStorage[existingIndexes[i]];
        for (int z = 0; z < Z; z++) {
            Block curBlock = bucket.blocks[z];
            Node* node = convertBlockToNode(curBlock.data);
            bool cond = Node::CTeq(node->index, (unsigned long long) 0);
            bool key_mathces = Node::CTeq(node->index, (unsigned long long) bid) && !cond;
            node->value = Node::conditional_select(node->value, (unsigned long long) 0, !cond);
            node->isDummy = Node::conditional_select(0, 1, !cond);
            curBlock.isDummy = node->isDummy;
            block_num = Node::conditional_select(block_num, block_num + 1, node->isDummy || key_mathces);
            Node::conditional_assign(insertNode, node, key_mathces);

            Node::conditional_assign(curBlock.data, zero, key_mathces);
            curBlock.isDummy = Node::conditional_select(true, curBlock.isDummy, key_mathces);
            delete node;
        }
        bucket.num_blocks = block_num;
        virtualStorage[existingIndexes[i]] = bucket;
    }

    ConditionalInsert(insertNode, !insertNode->isDummy);
    delete insertNode;

}


// Gets the data of a block in the stash

// Fetches a block, allowing you to read and write in a block

unsigned long long ORAM::Access(unsigned long long bid, unsigned long long pos, unsigned long long& content, bool batchAccess) {
    if (bid == 0) {
        throw runtime_error("Node id is not set");
    }

    if (batchAccess) {
        FetchBatchPath(pos, bid);
    } else {
        FetchPath(pos, bid);
    }

    unsigned long long newPos = RandomPath();
    bool write = !Node::CTeq(content, (unsigned long long) 0);
    for (Node* node : stash.blocks) {
        bool choice = Node::CTeq(0, Node::CTcmp(node->index, bid));
        content = Node::conditional_select(node->value, content, choice && !write);
        node->value = Node::conditional_select(content, node->value, choice && write);
        node->pos = Node::conditional_select(newPos, node->pos, choice);
    }
    if (batchAccess) {
        leafList.insert(pos);
    } else {
        leaf = pos;
    }
    return newPos;
}

Node* ORAM::convertBlockToNode(std::array<byte_t, sizeof (Node) > b) {
    Node* node = new Node();
    from_bytes(b, *node);
    return node;
}

std::array<byte_t, sizeof (Node) > ORAM::convertNodeToBlock(Node* node) {
    std::array<byte_t, sizeof (Node) > data = to_bytes(*node);
    return data;
}

void ORAM::Evict(bool batchEvict) {
    num_writes++;
    if (num_writes % THRESHOLD == 0) {
        //        ocall_start_timer(55);
        if (batchEvict) {
            BatchSlowEvict();
        } else {
            SlowEvict();
        }

        //        double dd;
        //        ocall_stop_timer(&dd, 55);
        //        printf("slow evict time:%f\n", dd);
    } else {
        //        ocall_start_timer(55);
        if (batchEvict) {
            BatchFastEvict();
        } else {
            FastEvict();
        }
        //        double dd;
        //        ocall_stop_timer(&dd, 55);
        //        printf("fast evict time:%f\n", dd);
    }
}

void ORAM::FastEvict() {
    int allblockSize = PERMANENT_STASH_SIZE;
    Node** allblocks = new Node*[allblockSize];
    for (int i = 0; i < PERMANENT_STASH_SIZE; i++) {
        allblocks[i] = stash.blocks[i];
        allblocks[i]->evictionNode = 0;
    }

    unsigned long long random_position = RandomPath();
    for (int i = 0; i < PERMANENT_STASH_SIZE; i++) {
        Node* block = allblocks[i];
        bool found = false;
        long long match_node = 0;
        long long current_matched_node = 0;
        int new_fullness = stash.pathBuckets[stash.pathSize - 1].num_blocks;
        int current_fullness = new_fullness;

        long long search_pos = Node::conditional_select(random_position, block->pos, block->isDummy);

        long long node = search_pos;
        node += bucketCount / 2;
        for (int d = (int) depth; d >= 0; d--) {
            int fullness = -1;
            for (int j = 0; j < stash.pathSize; j++) {
                bool key_mathces = Node::CTeq(stash.pathIndexes[j], node);
                fullness = Node::conditional_select(stash.pathBuckets[j].num_blocks, fullness, key_mathces);
            }
            bool path_intersects = !Node::CTeq(fullness, -1);
            bool has_space = path_intersects && Node::CTeq(Node::CTcmp(fullness, Z), -1);
            new_fullness = Node::conditional_select(fullness + 1, new_fullness, has_space && !found);
            match_node = Node::conditional_select(node, match_node, has_space && !found);
            found = found || has_space;

            node = (node + 1) / 2 - 1;
        }

        new_fullness = Node::conditional_select(current_fullness, new_fullness, block->isDummy);
        match_node = Node::conditional_select(current_matched_node, match_node, block->isDummy);

        for (int j = 0; j < stash.pathSize; j++) {
            bool key_mathces = Node::CTeq(stash.pathIndexes[j], match_node);
            Node::conditional_assign(&stash.pathBuckets[j].num_blocks, &new_fullness, key_mathces);
        }


        block->evictionNode = Node::conditional_select(block->evictionNode, match_node, block->isDummy);
    }

    std::array < bool, PERMANENT_STASH_SIZE> inserted_status;

    for (int i = 0; i < PERMANENT_STASH_SIZE; i++) {
        Node* block = allblocks[i];
        long long assigned_node = block->evictionNode;
        std::array<byte_t, sizeof (Node) > tmp = convertNodeToBlock(block);
        bool inserted = false;
        for (int j = 0; j < stash.pathSize; j++) {
            long long node = stash.pathIndexes[j];
            Bucket& bucket = stash.pathBuckets[j];
            bool nodes_match = Node::CTeq(assigned_node, node) && !block->isDummy;
            bool inserted_now = false;
            for (int z = 0; z < Z; z++) {
                Block& cur_block = bucket.blocks[z];
                bool should_insert = nodes_match && !inserted && cur_block.isDummy;
                inserted = inserted || should_insert;
                inserted_now = inserted_now || should_insert;

                for (int k = 0; k < tmp.size(); k++) {
                    Node::conditional_assign(&cur_block.data[k], &tmp[k], should_insert);
                }
                cur_block.isDummy = Node::conditional_select(false, cur_block.isDummy, should_insert);
            }
        }
        inserted_status[i] = inserted;
    }

    EvictBuckets();

    Node* dummy = new Node();
    dummy->index = 0;
    dummy->isDummy = true;
    dummy->value = 0;
    dummy->pos = 0;

    for (int i = 0; i < PERMANENT_STASH_SIZE; i++) {
        bool should_insert_dummy = inserted_status[i] || stash.blocks[i]->isDummy;
        Node::conditional_assign(stash.blocks[i], dummy, should_insert_dummy);
    }

    //    int stashCounter = 0;
    //    for (int i = 0; i < PERMANENT_STASH_SIZE; i++) {
    //        if (stash.blocks[i]->isDummy == false) {
    //            stashCounter++;
    //        }
    //    }
    //    printf("fast stash size:%d\n", stashCounter);

    delete dummy;
    delete allblocks;
}

void ORAM::BatchFastEvict() {
    int allblockSize = PERMANENT_STASH_SIZE;
    Node** allblocks = new Node*[allblockSize];
    for (int i = 0; i < PERMANENT_STASH_SIZE; i++) {
        allblocks[i] = stash.blocks[i];
        allblocks[i]->evictionNode = 0;
    }

    std::array<long long, 2000> finalIndexes;
    std::array<Bucket, 2000> finalBuckets;


    int bufuSize = virtualStorage.size();
    std::array<long long, 20000> BUFUIndex;
    std::array<int, 20000> BUFUFullness;


    std::array< long long, 40 > BUFULevels;

    vector<long long> uindexses;

    for (auto item : virtualStorage) {
        uindexses.push_back(item.first);
    }

    std::sort(uindexses.begin(), uindexses.end(), greater<long long>());

    long long curLevelIndex = bucketCount / 2;
    long long curLevel = depth;
    BUFULevels[curLevel] = 0;

    int counter = 0;
    for (int i = 0; i < uindexses.size(); i++) {
        BUFUIndex[i] = uindexses[i];

        BUFUFullness[counter] = virtualStorage[uindexses[i]].num_blocks;
        finalIndexes[counter] = uindexses[i];
        finalBuckets[counter++] = virtualStorage[uindexses[i]];
        if (uindexses[i] < curLevelIndex) {
            curLevel--;
            curLevelIndex = (curLevelIndex + 1) / 2 - 1;
            BUFULevels[curLevel] = i;
        }
    }

    unsigned long long random_position = RandomPath();
    for (int i = 0; i < PERMANENT_STASH_SIZE; i++) {
        Node* block = allblocks[i];
        bool found = false;
        long long match_node = 0;
        long long current_matched_node = 0;
        int new_fullness = virtualStorage[0].num_blocks;
        int current_fullness = new_fullness;

        long long search_pos = Node::conditional_select(random_position, block->pos, block->isDummy);

        long long node = search_pos;
        node += bucketCount / 2;
        for (int d = (int) depth; d >= 0; d--) {
            int fullness = -1;
            bool found2 = false;
            for (int j = BUFULevels[d]; j <= (d > 0 ? (BUFULevels[d - 1] - 1) : BUFULevels[d]); j++) {
                bool key_mathces = Node::CTeq(BUFUIndex[j], node);
                fullness = Node::conditional_select(BUFUFullness[j], fullness, key_mathces && !found2);
                found2 = found2 || key_mathces;

            }

            bool path_intersects = !Node::CTeq(fullness, -1);
            bool has_space = path_intersects && Node::CTeq(Node::CTcmp(fullness, Z), -1);
            new_fullness = Node::conditional_select(fullness + 1, new_fullness, has_space && !found);
            match_node = Node::conditional_select(node, match_node, has_space && !found);
            found = found || has_space;

            node = (node + 1) / 2 - 1;
        }

        new_fullness = Node::conditional_select(current_fullness, new_fullness, block->isDummy);
        match_node = Node::conditional_select(current_matched_node, match_node, block->isDummy);

        for (int j = 0; j < bufuSize; j++) {
            bool key_mathces = Node::CTeq(BUFUIndex[j], match_node) && !block->isDummy;
            BUFUFullness[j] = Node::conditional_select(new_fullness, BUFUFullness[j], key_mathces);

        }


        block->evictionNode = Node::conditional_select(block->evictionNode, match_node, block->isDummy);
    }

    std::array < bool, PERMANENT_STASH_SIZE> inserted_status;

    for (int i = 0; i < PERMANENT_STASH_SIZE; i++) {
        Node* block = allblocks[i];
        long long assigned_node = block->evictionNode;
        std::array<byte_t, sizeof (Node) > tmp = convertNodeToBlock(block);
        bool inserted = false;
        for (int j = 0; j < bufuSize; j++) {
            long long node = finalIndexes[j];
            Bucket& bucket = finalBuckets[j];
            bool nodes_match = Node::CTeq(assigned_node, node) && !block->isDummy;
            bool inserted_now = false;
            for (int z = 0; z < Z; z++) {
                Block& cur_block = bucket.blocks[z];
                bool should_insert = nodes_match && !inserted && cur_block.isDummy;
                inserted = inserted || should_insert;
                inserted_now = inserted_now || should_insert;

                for (int k = 0; k < tmp.size(); k++) {
                    Node::conditional_assign(&cur_block.data[k], &tmp[k], should_insert);
                }
                cur_block.isDummy = Node::conditional_select(false, cur_block.isDummy, should_insert);
                bucket.blocks[z] = cur_block;
            }
            finalBuckets[j] = bucket;
            finalBuckets[j].num_blocks = BUFUFullness[j];
        }
        inserted_status[i] = inserted;
    }

    EvictBuckets(&finalIndexes, &finalBuckets, counter);
    Node* dummy = new Node();
    dummy->index = 0;
    dummy->isDummy = true;
    dummy->value = 0;
    dummy->pos = 0;

    for (int i = 0; i < PERMANENT_STASH_SIZE; i++) {
        bool should_insert_dummy = inserted_status[i] || stash.blocks[i]->isDummy;
        Node::conditional_assign(stash.blocks[i], dummy, should_insert_dummy);
    }

    //        int stashCounter = 0;
    //        for (int i = 0; i < PERMANENT_STASH_SIZE; i++) {
    //            if (stash.blocks[i]->isDummy == false) {
    //                stashCounter++;
    //            }
    //        }
    //        printf("fast stash size:%d\n", stashCounter);

    delete dummy;
    delete allblocks;
}

void ORAM::SlowEvict() {
    double time;
    if (profile) {
        ocall_start_timer(15);
        ocall_start_timer(10);
    }

    for (Node* t : stash.blocks) {
        t->evictionNode = 0;
    }

    long long currentLeaf = leaf;

    long long BUFUIndex[PERMANENT_STASH_SIZE];
    int BUFUFullness[PERMANENT_STASH_SIZE];

    for (int i = 0; i < stash.pathSize; i++) {
        BUFUIndex[i] = stash.pathIndexes[i];
        BUFUFullness[i] = 0;
    }

    int allblockSize = PERMANENT_STASH_SIZE + stash.pathSize * Z * 2;
    Node** allblocks = new Node*[allblockSize];
    for (int i = 0; i < PERMANENT_STASH_SIZE; i++) {
        allblocks[i] = stash.blocks[i];
    }

    int counter = PERMANENT_STASH_SIZE;

    for (int i = 0; i < stash.pathSize; i++) {
        Bucket bucket = stash.pathBuckets[i];
        for (int z = 0; z < Z; z++) {
            Block &curBlock = bucket.blocks[z];
            Node* node = convertBlockToNode(curBlock.data);
            bool cond = Node::CTeq(node->index, (unsigned long long) 0);
            node->index = Node::conditional_select(node->index, (unsigned long long) 0, !cond);
            node->value = Node::conditional_select(node->value, (unsigned long long) 0, !cond);
            node->isDummy = Node::conditional_select(0, 1, !cond);
            allblocks[counter++] = node;
        }
    }

    if (profile) {
        ocall_stop_timer(&time, 10);
        printf("put all blocks in allblock:%f\n", time);
        ocall_start_timer(10);
    }

    for (int i = 0; i < PERMANENT_STASH_SIZE + stash.pathSize * Z; i++) {
        Node* b = allblocks[i];
        long long nodePos = b->pos;
        nodePos += bucketCount / 2;
        int newFullness = -1;
        long long buckID = 0;
        bool isAssignedBefore = false;

        for (int d = (int) depth; d >= 0; d--) {

            int fullness = -1;

            for (int j = 0; j < stash.pathSize; j++) {
                bool key_mathces = Node::CTeq(BUFUIndex[j], nodePos);
                fullness = Node::conditional_select(BUFUFullness[j], fullness, key_mathces);
            }

            bool pathIntersects = !Node::CTeq(fullness, -1);
            bool hasSpace = pathIntersects && (Node::CTeq(Node::CTcmp(fullness, Z), -1)) && !b->isDummy;
            newFullness = Node::conditional_select(fullness + 1, newFullness, hasSpace & !isAssignedBefore);
            buckID = Node::conditional_select(nodePos, buckID, hasSpace & !isAssignedBefore);

            isAssignedBefore = isAssignedBefore || hasSpace;

            nodePos = (nodePos + 1) / 2 - 1;
        }

        for (int j = 0; j < stash.pathSize; j++) {
            bool key_mathces = Node::CTeq(BUFUIndex[j], buckID);
            BUFUFullness[j] = Node::conditional_select(newFullness, BUFUFullness[j], key_mathces);
        }
        b->evictionNode = Node::conditional_select(b->evictionNode, buckID, b->isDummy);
    }

    if (profile) {
        ocall_stop_timer(&time, 10);
        printf("Creating and Filling BUFU:%f\n", time);
        ocall_start_timer(10);
    }

    for (int i = 0; i < stash.pathSize; i++) {
        for (long long j = 0; j < Z; j++) {
            bool dummyForBucktet = Node::CTeq(Node::CTcmp(j, BUFUFullness[i]), -1);
            Node* dummy = new Node();
            dummy->index = 0;
            dummy->evictionNode = Node::conditional_select((long long) 0, BUFUIndex[i], dummyForBucktet);
            dummy->isDummy = true;
            dummy->value = 0;
            dummy->pos = 0;
            allblocks[counter++] = dummy;
        }
    }

    if (profile) {
        ocall_stop_timer(&time, 10);
        printf("Adding Extra Dummy Blocks to fill the Buckets and update BUFU:%f\n", time);
        ocall_start_timer(10);
    }

    ObliviousOperations::oblixmergesort(&allblocks, allblockSize);

    if (profile) {
        ocall_stop_timer(&time, 10);
        printf("Oblivious Sort: %f\n", time);
        ocall_start_timer(10);
    }

    unsigned int j = 0;
    int bucketCounter = 0;
    Bucket* bucket = new Bucket();
    for (unsigned int i = 0; i < stash.pathSize * Z; i++) {
        Node* cureNode = allblocks[i];
        long long curBucketID = cureNode->evictionNode;
        Block &curBlock = (*bucket).blocks[j];
        curBlock.data.fill(0);
        std::array<byte_t, sizeof (Node) > tmp = convertNodeToBlock(cureNode);
        for (int k = 0; k < tmp.size(); k++) {
            curBlock.data[k] = Node::conditional_select(curBlock.data[k], tmp[k], cureNode->isDummy);
        }
        curBlock.isDummy = cureNode->isDummy;
        delete cureNode;
        j++;

        if (j == Z) {
            stash.pathIndexes[bucketCounter] = curBucketID;
            stash.pathBuckets[bucketCounter++] = (*bucket);
            delete bucket;
            bucket = new Bucket();
            j = 0;
        }
    }
    delete bucket;

    if (profile) {
        ocall_stop_timer(&time, 10);
        printf("Creating Buckets for write:%f\n", time);
        ocall_start_timer(10);
    }

    std::copy(allblocks + (stash.pathSize * Z), allblocks + (stash.pathSize * Z) + PERMANENT_STASH_SIZE, stash.blocks.begin());

    for (unsigned int i = (stash.pathSize * Z)+(int) PERMANENT_STASH_SIZE; i < allblockSize; i++) {
        delete allblocks[i];
    }

    if (profile) {
        ocall_stop_timer(&time, 10);
        printf("Padding Stash:%f\n", time);
        ocall_start_timer(10);
    }

    EvictBuckets();

    if (profile) {
        ocall_stop_timer(&time, 10);
        printf("Out of SGX memory write:%f\n", time);
    }

    if (profile) {
        ocall_stop_timer(&time, 15);
        evicttime += time;
        printf("eviction time:%f\n", time);
    }

    //    int stashCounter = 0;
    //    for (int i = 0; i < PERMANENT_STASH_SIZE; i++) {
    //        if (stash.blocks[i]->isDummy == false) {
    //            stashCounter++;
    //        }
    //    }
    //    printf("slow stash size:%d\n", stashCounter);

    delete[] allblocks;
}

void ORAM::BatchSlowEvict() {
    std::array<long long, 2000> finalIndexes;
    std::array<Bucket, 2000> finalBuckets;
    int bufuSize = virtualStorage.size();
    std::array<long long, 20000> BUFUIndex;
    std::array<int, 20000> BUFUFullness;

    std::array< long long, 40 > BUFULevels;

    vector<long long> uindexses;

    for (auto item : virtualStorage) {
        uindexses.push_back(item.first);
    }

    std::sort(uindexses.begin(), uindexses.end(), greater<long long>());

    long long curLevelIndex = bucketCount / 2;
    long long curLevel = depth;
    BUFULevels[curLevel] = 0;
    int bufuCounter = 0;
    for (int i = 0; i < uindexses.size(); i++) {

        BUFUIndex[i] = uindexses[i];
        BUFUFullness[bufuCounter] = 0;
        finalIndexes[bufuCounter] = uindexses[i];
        finalBuckets[bufuCounter++] = virtualStorage[uindexses[i]];


        if (uindexses[i] < curLevelIndex) {
            curLevel--;
            curLevelIndex = (curLevelIndex + 1) / 2 - 1;
            BUFULevels[curLevel] = i;
        }
    }
    int allblockSize = PERMANENT_STASH_SIZE + bufuSize * Z * 2;
    Node** allblocks = new Node*[allblockSize];
    for (int i = 0; i < PERMANENT_STASH_SIZE; i++) {
        allblocks[i] = stash.blocks[i];
    }

    int counter = PERMANENT_STASH_SIZE;
    int tmp = 0;
    for (int i = 0; i < bufuSize; i++) {
        long long index = finalIndexes[i];
        Bucket bucket = finalBuckets[i];
        for (int z = 0; z < Z; z++) {
            Block &curBlock = bucket.blocks[z];
            Node* node = convertBlockToNode(curBlock.data);
            bool cond = Node::CTeq(node->index, (unsigned long long) 0);
            node->index = Node::conditional_select(node->index, (unsigned long long) 0, !cond);
            node->isDummy = Node::conditional_select(0, 1, !cond);
            if (node->index != 0) {
                tmp++;
            }
            allblocks[counter++] = node;
        }
    }


    for (int i = 0; i < counter; i++) {
        Node* b = allblocks[i];
        b->evictionNode = 0;
        long long nodePos = b->pos;
        nodePos += bucketCount / 2;
        int newFullness = 0;
        long long buckID = 0;
        bool isAssignedBefore = false;

        for (int d = (int) depth; d >= 0; d--) {
            int fullness = -1;
            bool found2 = false;
            for (int j = BUFULevels[d]; j <= (d > 0 ? (BUFULevels[d - 1] - 1) : BUFULevels[d]); j++) {
                bool key_mathces = Node::CTeq(BUFUIndex[j], nodePos);
                fullness = Node::conditional_select(BUFUFullness[j], fullness, key_mathces && !found2);
                found2 = found2 || key_mathces;
            }

            bool pathIntersects = !Node::CTeq(fullness, -1);
            bool hasSpace = pathIntersects && (Node::CTeq(Node::CTcmp(fullness, Z), -1)) && !b->isDummy;
            newFullness = Node::conditional_select(fullness + 1, newFullness, hasSpace & !isAssignedBefore);
            buckID = Node::conditional_select(nodePos, buckID, hasSpace & !isAssignedBefore);

            isAssignedBefore = isAssignedBefore || hasSpace;

            nodePos = (nodePos + 1) / 2 - 1;
        }
        for (int j = 0; j < bufuSize; j++) {
            bool key_mathces = Node::CTeq(BUFUIndex[j], buckID);
            BUFUFullness[j] = Node::conditional_select(newFullness, BUFUFullness[j], key_mathces);
        }
        b->evictionNode = buckID;
    }


    for (int i = 0; i < bufuSize; i++) {
        for (long long j = 0; j < Z; j++) {
            bool dummyForBucktet = Node::CTeq(Node::CTcmp(j, BUFUFullness[i]), -1);
            Node* dummy = new Node();
            dummy->index = 0;
            dummy->evictionNode = Node::conditional_select((long long) 0, BUFUIndex[i], dummyForBucktet);
            dummy->isDummy = true;
            dummy->value = 0;
            dummy->pos = 0;
            allblocks[counter++] = dummy;
        }
    }

    ObliviousOperations::oblixmergesort(&allblocks, allblockSize);

    unsigned int j = 0;
    int bucketCounter = 0;
    Bucket* bucket = new Bucket();
    for (unsigned int i = 0; i < bufuSize * Z; i++) {
        Node* cureNode = allblocks[i];
        long long curBucketID = cureNode->evictionNode;
        Block &curBlock = (*bucket).blocks[j];
        curBlock.data.fill(0);
        std::array<byte_t, sizeof (Node) > tmp = convertNodeToBlock(cureNode);
        for (int k = 0; k < tmp.size(); k++) {
            Node::conditional_assign(&curBlock.data[k], &tmp[k], !cureNode->isDummy);
        }
        curBlock.isDummy = cureNode->isDummy;
        bucket->num_blocks = Node::conditional_select(bucket->num_blocks, bucket->num_blocks + 1, cureNode->isDummy);

        delete cureNode;
        j++;

        if (j == Z) {
            finalIndexes[bucketCounter] = curBucketID;
            finalBuckets[bucketCounter++] = (*bucket);
            delete bucket;
            bucket = new Bucket();
            j = 0;
        }
    }
    delete bucket;

    EvictBuckets(&finalIndexes, &finalBuckets, bucketCounter);

    std::copy(allblocks + (bufuSize * Z), allblocks + (bufuSize * Z) + PERMANENT_STASH_SIZE, stash.blocks.begin());

    for (unsigned int i = (bufuSize * Z)+(int) PERMANENT_STASH_SIZE; i < allblockSize; i++) {
        delete allblocks[i];
    }

    //        int stashCounter = 0;
    //        for (int i = 0; i < PERMANENT_STASH_SIZE; i++) {
    //            if (stash.blocks[i]->isDummy == false) {
    //                stashCounter++;
    //            }
    //        }
    //        printf("slow stash size:%d\n", stashCounter);

    leafList.clear();

    delete[] allblocks;
}

unsigned long long ORAM::RandomPath() {
    uint32_t val;
    sgx_read_rand((unsigned char *) &val, 4);
    return val % (maxOfRandom);
}

ORAM::ORAM(long long maxSize, bytes<Key> oram_key, vector<Node*>* nodes)
: key(oram_key) {
    depth = (int) (ceil(log2(maxSize)) - 1) + 1;
    maxOfRandom = (long long) (pow(2, depth));
    Crypto::Setup();
    bucketCount = maxOfRandom * 2 - 1;
    printf("Number of leaves:%lld\n", maxOfRandom);
    printf("depth:%lld\n", depth);

    blockSize = sizeof (Node); // B  
    printf("block size is:%d\n", blockSize);
    size_t blockCount = (size_t) (Z * bucketCount);
    storeBlockSize = (size_t) (IV + Crypto::GetCiphertextLength((int) (Z * (blockSize))));
    clen_size = Crypto::GetCiphertextLength((int) (blockSize) * Z);
    plaintext_size = (blockSize) * Z;
    ocall_setup_ramStore(blockCount, storeBlockSize);
    maxHeightOfAVLTree = (int) floor(log2(blockCount)) + 1;


    unsigned long long tree_size = bucketCount;
    long long num_levels = log2(tree_size + 1);
    long long i = 0;
    unsigned long long level_size = ((tree_size + 1) / 2);
    long long level_start_node = bucketCount / 2;
    vector<BlockInfo*> blocks_info;
    vector < pair<unsigned long long, unsigned long long> > server;

    blocks_info.reserve(level_size);

    for (i = 0; i < nodes->size(); i++) {
        BlockInfo* tmp = new BlockInfo();
        tmp->i = i;
        tmp->pos = (*nodes)[i]->pos + level_start_node;
        tmp->isInBucket = 0;
        blocks_info.push_back(tmp);
    }


    for (int d = 0; d < num_levels; d++) {
        int stash_size = blocks_info.size();

        if (stash_size > level_size * Z * 2) {
            int m = std::max((unsigned long long) PERMANENT_STASH_SIZE, level_size * Z * 2);
            blocks_info.erase(blocks_info.begin() + m, blocks_info.end());
        }
        stash_size = blocks_info.size();
        unsigned long long current_node = level_start_node;

        for (int i = 0; i < level_size; i++) {
            for (int j = 0; j < Z; j++) {
                BlockInfo* tmp = new BlockInfo;
                tmp->i = 0;
                tmp->isInBucket = 0;
                tmp->pos = current_node;
                blocks_info.push_back(tmp);
            }
            current_node++;
        }

        ObliviousOperations::bitonicSort(&blocks_info, true);

        current_node = level_start_node;
        long long current_node_count = 0;
        for (int i = 0; i < blocks_info.size(); i++) {
            BlockInfo* curNode = blocks_info[i];
            bool node_match = Node::CTeq(curNode->pos, current_node);
            current_node_count = Node::conditional_select((long long) 0, current_node_count, !node_match);
            current_node = curNode->pos;
            curNode->isInBucket = Node::conditional_select(1, 0, Node::CTeq(Node::CTcmp(current_node_count, Z), -1));
            current_node_count += 1;
        }

        ObliviousOperations::bitonicSort(&blocks_info, false);

        for (int i = stash_size; i < blocks_info.size(); i++) {
            server.push_back(pair<unsigned long long, unsigned long long>(blocks_info[i]->i, blocks_info[i]->pos));
        }

        for (int i = stash_size; i < blocks_info.size(); i++) {
            delete blocks_info[i];
        }

        blocks_info.erase(blocks_info.begin() + stash_size, blocks_info.end());


        level_size /= 2;
        level_start_node = (level_start_node + 1) / 2 - 1;

        for (int i = 0; i < blocks_info.size(); i++) {
            blocks_info[i]->pos = (blocks_info[i]->pos + 1) / 2 - 1;
        }
    }

    for (int i = PERMANENT_STASH_SIZE; i < blocks_info.size(); i++) {
        delete blocks_info[i];
    }
    blocks_info.erase(blocks_info.begin() + PERMANENT_STASH_SIZE, blocks_info.end());

    for (int i = 0; i < blocks_info.size(); i++) {
        server.push_back(pair<unsigned long long, unsigned long long>(blocks_info[i]->i, blocks_info[i]->pos));
    }

    ObliviousOperations::bitonicSort(&server);

    int neededDummy = server.size() - nodes->size();
    for (int i = 0; i < neededDummy; i++) {
        Node* dummy = new Node();
        dummy->index = 0;
        dummy->isDummy = true;
        dummy->pos = 0;
        dummy->evictionNode = 0;
        nodes->push_back(dummy);
    }

    vector<pair<unsigned long long, Node*> > blocks_server;
    for (int i = 0; i < nodes->size(); i++) {
        blocks_server.push_back(pair<unsigned long long, Node*>(server[i].second, (*nodes)[i]));
    }

    ObliviousOperations::bitonicSort(&blocks_server);

    vector<long long> indexes;
    vector<Bucket> buckets;

    unsigned int j = 0;
    Bucket* bucket = new Bucket();
    for (unsigned int i = 0; i < tree_size * Z; i++) {
        if (i % 100000 == 0 && i != 0) {
            printf("Creating Buckets:%d/%d\n", i, nodes->size());
        }
        Node* cureNode = blocks_server[i].second;
        long long curBucketID = blocks_server[i].first;

        Block &curBlock = (*bucket).blocks[j];
        curBlock.data.fill(0);
        std::array<byte_t, sizeof (Node) > tmp = convertNodeToBlock(cureNode);
        for (int k = 0; k < tmp.size(); k++) {
            curBlock.data[k] = Node::conditional_select(curBlock.data[k], tmp[k], cureNode->isDummy);
        }
        delete cureNode;
        j++;

        if (j == Z) {
            indexes.push_back(curBucketID);
            buckets.push_back((*bucket));
            delete bucket;
            bucket = new Bucket();
            j = 0;
        }
    }
    delete bucket;

    for (unsigned int j = 0; j <= indexes.size() / 10000; j++) {
        char* tmp = new char[10000 * storeBlockSize];
        size_t cipherSize = 0;
        Crypto::refreshIV(stash.pathSize);
        for (int i = 0; i < min((int) (indexes.size() - j * 10000), 10000); i++) {
            BucketBytes b = SerialiseBucket(buckets[j * 10000 + i]);
            EncBucketBytes ciphertext = Crypto::Encrypt(key, b, clen_size, plaintext_size, i);
            std::copy(ciphertext.begin(), ciphertext.end(), tmp + i * ciphertext.size());
            cipherSize = ciphertext.size();
        }
        if (min((int) (indexes.size() - j * 10000), 10000) != 0) {
            ocall_nwrite_ramStore(min((int) (indexes.size() - j * 10000), 10000), indexes.data() + j * 10000, (const char*) tmp, cipherSize * min((int) (indexes.size() - j * 10000), 10000));
        }
        delete tmp;
    }

    j = 0;
    for (i = tree_size * Z; i < blocks_server.size() && j < PERMANENT_STASH_SIZE; i++, j++) {
        stash.blocks[j] = blocks_server[i].second;
    }

}

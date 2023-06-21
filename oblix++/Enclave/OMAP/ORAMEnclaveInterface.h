#ifndef ORAMENCLAVEINTERFACE_H
#define ORAMENCLAVEINTERFACE_H

#include "../Enclave.h"
#include "Enclave_t.h"
#include "ORAM.hpp"
#include <string>
#include "Crypto.h"

void check_memory(string text) {
    unsigned int required = 0x4f00000; // adapt to native uint
    char *mem = NULL;
    while (mem == NULL) {
        mem = (char*) malloc(required);
        if ((required -= 8) < 0xFFF) {
            if (mem) free(mem);
            printf("Cannot allocate enough memory\n");
            return;
        }
    }

    free(mem);
    mem = (char*) malloc(required);
    if (mem == NULL) {
        printf("Cannot enough allocate memory\n");
        return;
    }
    printf("%s = %d\n", text.c_str(), required);
    free(mem);
}

double ecall_measure_oram_speed(int testSize) {
    bytes<Key> tmpkey{0};
    double time1, time2, total = 0;
    int depth = (int) (ceil(log2(testSize)) - 1) + 1;
    int maxSize = (int) (pow(2, depth));
    ORAM* oram = new ORAM(maxSize, tmpkey, false);
    map<unsigned long long, unsigned long long> PositionsMap;
    printf("Warming up the ORAM by dummy operations:\n");
    for (int i = 1; i <= 1000; i++) {
        if (i % 1000 == 0) {
            printf("%d/%d\n", i, 10000);
        }
        uint32_t randval;
        sgx_read_rand((unsigned char *) &randval, 4);
        unsigned long long id = (i % (maxSize - 1)) + 1;
        unsigned long long value = i;
        long long pos;

        if (PositionsMap.count(id) == 0) {
            pos = id;
        } else {
            pos = PositionsMap[id];
        }
        pos = oram->Access(id, pos, value);
        oram->Evict();
        unsigned long long res = 0;
        pos = oram->Access(id, pos, res);
        oram->Evict();
        PositionsMap[id] = pos;
        assert(value == res);
    }

    total = 0;
    //    oram->profile = true;
    for (int j = 0; j < 500; j++) {
        uint32_t randval;
        sgx_read_rand((unsigned char *) &randval, 4);
        unsigned long long id = (j % (maxSize - 1)) + 1;
        unsigned long long value = j;
        long long pos;
        if (PositionsMap.count(id) == 0) {
            pos = id;
        } else {
            pos = PositionsMap[id];
        }
        ocall_start_timer(535);
        pos = oram->Access(id, pos, value);
        oram->Evict();
        ocall_stop_timer(&time1, 535);
        printf("access time:%f\n", time1);
        unsigned long long res = 0;
        ocall_start_timer(535);
        pos = oram->Access(id, pos, res);
        oram->Evict();
        ocall_stop_timer(&time2, 535);
        printf("access time:%f\n", time2);
        PositionsMap[id] = pos;
        assert(value == res);
        total += time1 + time2;
    }
    printf("Total Access Time: %f\n", total / 1000);

    return 0;
}

double ecall_measure_batch_speed(int testSize) {
    bytes<Key> tmpkey{0};
    double time1, time2, total = 0;
    int depth = (int) (ceil(log2(testSize)) - 1) + 1;
    int maxSize = (int) (pow(2, depth));
    ORAM* oram = new ORAM(maxSize, tmpkey, false);
    map<unsigned long long, unsigned long long> PositionsMap;
    printf("Warming up the ORAM by dummy operations:\n");
    for (int i = 1; i <= 1000; i++) {
        if (i % 1000 == 0) {
            printf("%d/%d\n", i, 10000);
            check_memory("");
        }
        uint32_t randval;
        sgx_read_rand((unsigned char *) &randval, 4);
        unsigned long long id = (i % (maxSize - 1)) + 1;
        unsigned long long value = i;
        long long pos;

        if (PositionsMap.count(id) == 0) {
            pos = id;
        } else {
            pos = PositionsMap[id];
        }
        pos = oram->Access(id, pos, value);
        oram->Evict();
        unsigned long long res = 0;
        pos = oram->Access(id, pos, res);
        oram->Evict();
        PositionsMap[id] = pos;
        assert(value == res);
    }

    double totAverage = 0;
    for (int i = 0; i < 100; i++) {
        total = 0;
        for (int j = 0; j < depth * 1.44/2; j++) {
            uint32_t randval;
            sgx_read_rand((unsigned char *) &randval, 4);
            unsigned long long id = (j % (maxSize - 1)) + 1;
            unsigned long long value = j;
            long long pos;
            if (PositionsMap.count(id) == 0) {
                pos = id;
            } else {
                pos = PositionsMap[id];
            }
            ocall_start_timer(535);
            pos = oram->Access(id, pos, value, true);
            ocall_stop_timer(&time1, 535);
            unsigned long long res = 0;
            ocall_start_timer(535);
            pos = oram->Access(id, pos, res, true);
            ocall_stop_timer(&time2, 535);
            PositionsMap[id] = pos;
            assert(value == res);
            total += time1 + time2;
        }
        double time3;
        ocall_start_timer(535);
        oram->Evict(true);
        ocall_stop_timer(&time3, 535);
        total += time3;
        totAverage += total;
        printf("Batch Time: %f\n", total);
        printf("Time per Access: %f\n", total / (depth * 1.44/2));
    }
    printf("Average Batch Time: %f\n", totAverage / 100);

    return 0;
}

double ecall_measure_setup_speed(int testSize) {
    vector<Node*> nodes;
    int depth = (int) (ceil(log2(testSize)) - 1) + 1;
    long long maxSize = (int) (pow(2, depth));
    for (int i = 0; i < maxSize; i++) {
        Node* tmp = new Node();
        tmp->index = i + 1;
        tmp->value = i + 1;
        uint32_t randval;
        sgx_read_rand((unsigned char *) &randval, 4);
        tmp->pos = randval % maxSize;
        nodes.push_back(tmp);
    }
    bytes<Key> tmpkey{0};
    double time2;
    ocall_start_timer(535);
    ORAM* oram = new ORAM(maxSize, tmpkey, &nodes);
    ocall_stop_timer(&time2, 535);
    printf("Setup time is:%f\n", time2);

    //    vector<string> names;
    //    names.push_back("Iterate Levels:");
    //    names.push_back("Add Dummy:");
    //    names.push_back("Sort:");
    //    names.push_back("Write Buckets:");
    //
    //    for (int i = 0; i < names.size(); i++) {
    //        printf("%s\n", names[i].c_str());
    //        for (int j = 0; j < oram->times[i].size(); j++) {
    //            printf("%f\n", oram->times[i][j]);
    //        }
    //    }
}

#define ARRAY_TEST_SIZE 10000
#define NUMBER_OF_OPERATIONS 10000

void ecall_data_structure_benchmark() {

    char charStack[ARRAY_TEST_SIZE];
    int intStack[ARRAY_TEST_SIZE];
    long long longlongStack[ARRAY_TEST_SIZE];

    char* charHeap = new char[ARRAY_TEST_SIZE];
    int* intHeap = new int[ARRAY_TEST_SIZE];
    long long* longlongHeap = new long long[ARRAY_TEST_SIZE];

    std::vector<char> charVector(ARRAY_TEST_SIZE, 0);
    std::vector<char> charVectorPushBack;
    std::vector<int> intVector(ARRAY_TEST_SIZE, 0);
    std::vector<int> intVectorPushBack;
    std::vector<long long> longlongVector(ARRAY_TEST_SIZE, 0);
    std::vector<long long> longlongVectorPushBack;

    std::array<char, ARRAY_TEST_SIZE> charArray;
    std::array<int, ARRAY_TEST_SIZE> intArray;
    std::array<long long, ARRAY_TEST_SIZE>longlongArray;

    long long longTest;
    int intTest;
    char charTest;

    double t;

    int randomPos[NUMBER_OF_OPERATIONS];
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        uint32_t val;
        sgx_read_rand((unsigned char *) &val, 4);
        randomPos[i] = val % (ARRAY_TEST_SIZE);
    }

    printf("----------------------------------------------------------------------\n");
    printf("Sequential char ARRAY Write Time:\n\n");

    printf("Stack Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        charStack[i % ARRAY_TEST_SIZE] = 3;
    }
    ocall_stop_timer(&t, 34);
    printf("Time per write:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("Heap Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        charHeap[i % ARRAY_TEST_SIZE] = 3;
    }
    ocall_stop_timer(&t, 34);
    printf("Time per write:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("Vector Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        charVector[i % ARRAY_TEST_SIZE] = 3;
    }
    ocall_stop_timer(&t, 34);
    printf("Time per write:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("Vector Array Push Back:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        charVectorPushBack.push_back(3);
    }
    ocall_stop_timer(&t, 34);
    printf("Time per write:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("std::Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        charArray[i % ARRAY_TEST_SIZE] = 3;
    }
    ocall_stop_timer(&t, 34);
    printf("Time per write:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("----------------------------------------------------------------------\n");
    printf("Sequential int ARRAY Write Time:\n\n");

    printf("Stack Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        intStack[i % ARRAY_TEST_SIZE] = 3;
    }
    ocall_stop_timer(&t, 34);
    printf("Time per write:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("Heap Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        intHeap[i % ARRAY_TEST_SIZE] = 3;
    }
    ocall_stop_timer(&t, 34);
    printf("Time per write:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("Vector Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        intVector[i % ARRAY_TEST_SIZE] = 3;
    }
    ocall_stop_timer(&t, 34);
    printf("Time per write:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("Vector Array Push Back:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        intVectorPushBack.push_back(3);
    }
    ocall_stop_timer(&t, 34);
    printf("Time per write:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("std::Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        intArray[i % ARRAY_TEST_SIZE] = 3;
    }
    ocall_stop_timer(&t, 34);
    printf("Time per write:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("----------------------------------------------------------------------\n");
    printf("Sequential long long ARRAY Write Time:\n\n");

    printf("Stack Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        longlongStack[i % ARRAY_TEST_SIZE] = 3;
    }
    ocall_stop_timer(&t, 34);
    printf("Time per write:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("Heap Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        longlongHeap[i % ARRAY_TEST_SIZE] = 3;
    }
    ocall_stop_timer(&t, 34);
    printf("Time per write:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("Vector Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        longlongVector[i % ARRAY_TEST_SIZE] = 3;
    }
    ocall_stop_timer(&t, 34);
    printf("Time per write:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("Vector Array Push Back:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        longlongVectorPushBack.push_back(3);
    }
    ocall_stop_timer(&t, 34);
    printf("Time per write:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("std::Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        longlongArray[i % ARRAY_TEST_SIZE] = 3;
    }
    ocall_stop_timer(&t, 34);
    printf("Time per write:%f microseconds\n", t / NUMBER_OF_OPERATIONS);


    printf("##################################################################################################################\n");
    printf("##################################################################################################################\n");
    printf("##################################################################################################################\n");
    printf("----------------------------------------------------------------------\n");
    printf("Sequential char ARRAY read Time:\n\n");

    printf("Stack Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        charTest = charStack[i % ARRAY_TEST_SIZE];
    }
    ocall_stop_timer(&t, 34);
    printf("Time per read:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("Heap Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        charTest = charHeap[i % ARRAY_TEST_SIZE];
    }
    ocall_stop_timer(&t, 34);
    printf("Time per read:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("Vector Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        charTest = charVector[i % ARRAY_TEST_SIZE];
    }
    ocall_stop_timer(&t, 34);
    printf("Time per read:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("std::Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        charTest = charArray[i % ARRAY_TEST_SIZE];
    }
    ocall_stop_timer(&t, 34);
    printf("Time per read:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("----------------------------------------------------------------------\n");
    printf("Sequential int ARRAY read Time:\n\n");

    printf("Stack Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        intTest = intStack[i % ARRAY_TEST_SIZE];
    }
    ocall_stop_timer(&t, 34);
    printf("Time per read:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("Heap Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        intTest = intHeap[i % ARRAY_TEST_SIZE];
    }
    ocall_stop_timer(&t, 34);
    printf("Time per read:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("Vector Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        intTest = intVector[i % ARRAY_TEST_SIZE];
    }
    ocall_stop_timer(&t, 34);
    printf("Time per read:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("std::Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        intTest = intArray[i % ARRAY_TEST_SIZE];
    }
    ocall_stop_timer(&t, 34);
    printf("Time per read:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("----------------------------------------------------------------------\n");
    printf("Sequential long long ARRAY read Time:\n\n");

    printf("Stack Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        longTest = longlongStack[i % ARRAY_TEST_SIZE];
    }
    ocall_stop_timer(&t, 34);
    printf("Time per read:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("Heap Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        longTest = longlongHeap[i % ARRAY_TEST_SIZE];
    }
    ocall_stop_timer(&t, 34);
    printf("Time per read:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("Vector Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        longTest = longlongVector[i % ARRAY_TEST_SIZE];
    }
    ocall_stop_timer(&t, 34);
    printf("Time per read:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("std::Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        longTest = longlongArray[i % ARRAY_TEST_SIZE];
    }
    ocall_stop_timer(&t, 34);
    printf("Time per read:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    //---------------------------------------------------------------------------------------------------------
    //---------------------------------------------------------------------------------------------------------
    //---------------------------------------------------------------------------------------------------------
    //---------------------------------------------------------------------------------------------------------
    //---------------------------------------------------------------------------------------------------------

    printf("##################################################################################################################\n");
    printf("##################################################################################################################\n");
    printf("##################################################################################################################\n");
    printf("----------------------------------------------------------------------\n");
    printf("Random char ARRAY Write Time:\n\n");

    printf("Stack Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        charStack[randomPos[i]] = 3;
    }
    ocall_stop_timer(&t, 34);
    printf("Time per write:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("Heap Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        charHeap[randomPos[i]] = 3;
    }
    ocall_stop_timer(&t, 34);
    printf("Time per write:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("Vector Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        charVector[randomPos[i]] = 3;
    }
    ocall_stop_timer(&t, 34);
    printf("Time per write:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("std::Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        charArray[randomPos[i]] = 3;
    }
    ocall_stop_timer(&t, 34);
    printf("Time per write:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("----------------------------------------------------------------------\n");
    printf("Random int ARRAY Write Time:\n\n");

    printf("Stack Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        intStack[randomPos[i]] = 3;
    }
    ocall_stop_timer(&t, 34);
    printf("Time per write:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("Heap Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        intHeap[randomPos[i]] = 3;
    }
    ocall_stop_timer(&t, 34);
    printf("Time per write:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("Vector Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        intVector[randomPos[i]] = 3;
    }
    ocall_stop_timer(&t, 34);
    printf("Time per write:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("std::Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        intArray[randomPos[i]] = 3;
    }
    ocall_stop_timer(&t, 34);
    printf("Time per write:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("----------------------------------------------------------------------\n");
    printf("Random long long ARRAY Write Time:\n\n");

    printf("Stack Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        longlongStack[randomPos[i]] = 3;
    }
    ocall_stop_timer(&t, 34);
    printf("Time per write:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("Heap Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        longlongHeap[randomPos[i]] = 3;
    }
    ocall_stop_timer(&t, 34);
    printf("Time per write:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("Vector Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        longlongVector[randomPos[i]] = 3;
    }
    ocall_stop_timer(&t, 34);
    printf("Time per write:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("std::Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        longlongArray[randomPos[i]] = 3;
    }
    ocall_stop_timer(&t, 34);
    printf("Time per write:%f microseconds\n", t / NUMBER_OF_OPERATIONS);


    printf("##################################################################################################################\n");
    printf("##################################################################################################################\n");
    printf("##################################################################################################################\n");
    printf("----------------------------------------------------------------------\n");
    printf("Random char ARRAY read Time:\n\n");

    printf("Stack Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        charTest = charStack[randomPos[i]];
    }
    ocall_stop_timer(&t, 34);
    printf("Time per read:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("Heap Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        charTest = charHeap[randomPos[i]];
    }
    ocall_stop_timer(&t, 34);
    printf("Time per read:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("Vector Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        charTest = charVector[randomPos[i]];
    }
    ocall_stop_timer(&t, 34);
    printf("Time per read:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("std::Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        charTest = charArray[randomPos[i]];
    }
    ocall_stop_timer(&t, 34);
    printf("Time per read:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("----------------------------------------------------------------------\n");
    printf("Random int ARRAY read Time:\n\n");

    printf("Stack Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        intTest = intStack[randomPos[i]];
    }
    ocall_stop_timer(&t, 34);
    printf("Time per read:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("Heap Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        intTest = intHeap[randomPos[i]];
    }
    ocall_stop_timer(&t, 34);
    printf("Time per read:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("Vector Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        intTest = intVector[randomPos[i]];
    }
    ocall_stop_timer(&t, 34);
    printf("Time per read:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("std::Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        intTest = intArray[randomPos[i]];
    }
    ocall_stop_timer(&t, 34);
    printf("Time per read:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("----------------------------------------------------------------------\n");
    printf("Random long long ARRAY read Time:\n\n");

    printf("Stack Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        longTest = longlongStack[randomPos[i]];
    }
    ocall_stop_timer(&t, 34);
    printf("Time per read:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("Heap Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        longTest = longlongHeap[randomPos[i]];
    }
    ocall_stop_timer(&t, 34);
    printf("Time per read:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("Vector Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        longTest = longlongVector[randomPos[i]];
    }
    ocall_stop_timer(&t, 34);
    printf("Time per read:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("std::Array:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        longTest = longlongArray[randomPos[i]];
    }
    ocall_stop_timer(&t, 34);
    printf("Time per read:%f microseconds\n", t / NUMBER_OF_OPERATIONS);


    //---------------------------------------------------------------------------------------------------------
    //---------------------------------------------------------------------------------------------------------
    //---------------------------------------------------------------------------------------------------------
    //---------------------------------------------------------------------------------------------------------
    //---------------------------------------------------------------------------------------------------------

    printf("##################################################################################################################\n");
    printf("##################################################################################################################\n");
    printf("##################################################################################################################\n");
    printf("----------------------------------------------------------------------\n");
    printf("Char MAP Write Time:\n\n");

    std::map<int, char> intToCharMap;
    std::map<int, int> intToIntMap;
    std::map<int, long long> intToLongLongMap;

    std::unordered_map<int, char> intToCharUMap;
    std::unordered_map<int, int> intToIntUMap;
    std::unordered_map<int, long long> intToLongLongUMap;

    printf("Char Map\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        intToCharMap[randomPos[i]] = 3;
    }
    ocall_stop_timer(&t, 34);
    printf("Time per write:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("Char UMap:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        intToCharUMap[randomPos[i]] = 3;
    }
    ocall_stop_timer(&t, 34);
    printf("Time per write:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("----------------------------------------------------------------------\n");
    printf("Int MAP Write Time:\n\n");


    printf("Int Map\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        intToIntMap[randomPos[i]] = 3;
    }
    ocall_stop_timer(&t, 34);
    printf("Time per write:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("Int UMap:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        intToIntUMap[randomPos[i]] = 3;
    }
    ocall_stop_timer(&t, 34);
    printf("Time per write:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("----------------------------------------------------------------------\n");
    printf("Long MAP Write Time:\n\n");


    printf("Long Map\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        intToLongLongMap[randomPos[i]] = 3;
    }
    ocall_stop_timer(&t, 34);
    printf("Time per write:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("Long UMap:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        intToLongLongUMap[randomPos[i]] = 3;
    }
    ocall_stop_timer(&t, 34);
    printf("Time per write:%f microseconds\n", t / NUMBER_OF_OPERATIONS);



    printf("##################################################################################################################\n");
    printf("##################################################################################################################\n");
    printf("##################################################################################################################\n");
    printf("----------------------------------------------------------------------\n");
    printf("Char MAP Read Time:\n\n");



    printf("Char Map\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        charTest = intToCharMap[randomPos[i]];
    }
    ocall_stop_timer(&t, 34);
    printf("Time per read:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("Char UMap:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        charTest = intToCharUMap[randomPos[i]];
    }
    ocall_stop_timer(&t, 34);
    printf("Time per read:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("----------------------------------------------------------------------\n");
    printf("Int MAP read Time:\n\n");



    printf("Int Map\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        intTest = intToIntMap[randomPos[i]];
    }
    ocall_stop_timer(&t, 34);
    printf("Time per read:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("Int UMap:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        intTest = intToIntUMap[randomPos[i]];
    }
    ocall_stop_timer(&t, 34);
    printf("Time per read:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("----------------------------------------------------------------------\n");
    printf("Long MAP read Time:\n\n");




    printf("Long Map\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        longTest = intToLongLongMap[randomPos[i]];
    }
    ocall_stop_timer(&t, 34);
    printf("Time per read:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

    printf("Long UMap:\n");
    ocall_start_timer(34);
    for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
        longTest = intToLongLongUMap[randomPos[i]];
    }
    ocall_stop_timer(&t, 34);
    printf("Time per read:%f microseconds\n", t / NUMBER_OF_OPERATIONS);

}

#endif /* ORAMENCLAVEINTERFACE_H */


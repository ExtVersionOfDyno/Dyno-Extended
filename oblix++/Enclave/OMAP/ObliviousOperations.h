#ifndef OBLIVIOUSOPERATIONS_H
#define OBLIVIOUSOPERATIONS_H

#include <vector>
#include <cassert>
#include <stdlib.h>
#include <array>
#include "ORAM.hpp"

using namespace std;

class ObliviousOperations {
private:
    static void bitonic_sort(vector<BlockInfo*>* nodes, int low, int n, int dir, bool firstSort);
    static void bitonic_merge(vector<BlockInfo*>* nodes, int low, int n, int dir, bool firstSort);
    static void compare_and_swap1(BlockInfo* item_i, BlockInfo* item_j, int dir);
    static void compare_and_swap2(BlockInfo* item_i, BlockInfo* item_j, int dir);

    static void bitonic_sort(vector<pair<unsigned long long, unsigned long long> >* nodes, int low, int n, int dir);
    static void bitonic_merge(vector<pair<unsigned long long, unsigned long long> >* nodes, int low, int n, int dir);
    static void compare_and_swap(pair<unsigned long long, unsigned long long> & item_i, pair<unsigned long long, unsigned long long> & item_j, int dir);

    static void bitonic_sort(vector<pair<unsigned long long, Node*> >* nodes, int low, int n, int dir);
    static void bitonic_merge(vector<pair<unsigned long long, Node*> >* nodes, int low, int n, int dir);
    static void compare_and_swap(pair<unsigned long long, Node*> & item_i, pair<unsigned long long, Node*> & item_j, int dir);

    static int greatest_power_of_two_less_than(int n);

public:
    ObliviousOperations();
    virtual ~ObliviousOperations();

    static void oblixmergesort(Node*** data, int size);
    static void bitonicSort(vector<BlockInfo*>* nodes, bool firstSort);
    static void bitonicSort(vector<pair<unsigned long long, unsigned long long> >* nodes);
    static void bitonicSort(vector<pair<unsigned long long, Node*> >* nodes);

};

#endif /* OBLIVIOUSOPERATIONS_H */


#ifndef NODE_H
#define NODE_H

#include "Bid.h"
#include <string>
#include <iostream>
#include <map>
#include <set>

class BlockInfo {
public:
    unsigned long long pos;
    unsigned int isInBucket;
    unsigned long long i;
};

class Node {
public:

    Node() {
    }

    ~Node() {
    }
    unsigned long long index;
    unsigned long long value;
    unsigned long long pos;
    long long evictionNode;
    bool isDummy;
    std::array< byte_t, 88> dum;

    static Node* clone(Node* oldNode) {
        Node* newNode = new Node();
        newNode->evictionNode = oldNode->evictionNode;
        newNode->index = oldNode->index;
        newNode->pos = oldNode->pos;
        newNode->value = oldNode->value;
        newNode->isDummy = oldNode->isDummy;
        newNode->dum = oldNode->dum;
        return newNode;
    }

    /**
     * constant time comparator
     * @param left
     * @param right
     * @return left < right -> -1,  left = right -> 0, left > right -> 1
     */
    static int CTcmp(long long lhs, long long rhs) {
        unsigned __int128 overflowing_iff_lt = (__int128) lhs - (__int128) rhs;
        unsigned __int128 overflowing_iff_gt = (__int128) rhs - (__int128) lhs;
        int is_less_than = (int) -(overflowing_iff_lt >> 127); // -1 if self < other, 0 otherwise.
        int is_greater_than = (int) (overflowing_iff_gt >> 127); // 1 if self > other, 0 otherwise.
        int result = is_less_than + is_greater_than;
        return result;
    }

    /**
     * constant time selector
     * @param a
     * @param b
     * @param choice 0 or 1
     * @return choice = 1 -> a , choice = 0 -> return b
     */
    static long long conditional_select(long long a, long long b, int choice) {
        unsigned long long one = 1;
        return (~((unsigned long long) choice - one) & a) | ((unsigned long long) (choice - one) & b);
    }

    /**
     * constant time selector
     * @param a
     * @param b
     * @param choice 0 or 1
     * @return choice = 1 -> a , choice = 0 -> return b
     */
    template<size_t SIZE>
    static std::array<byte_t, SIZE> conditional_select(std::array<byte_t, SIZE> a, std::array<byte_t, SIZE> b, int choice) {
        std::array<byte_t, SIZE> result;
        for (int i = 0; i < SIZE; i++) {
            result[i] = Node::conditional_select(a[i], b[i], choice);
        }
        return result;
    }

    template<size_t SIZE>
    static void conditional_assign(std::array<byte_t, SIZE>& a, std::array<byte_t, SIZE>& b, int choice) {
        for (int i = 0; i < SIZE; i++) {
            Node::conditional_assign(&a[i], &b[i], choice);
        }
    }

    static unsigned long long conditional_select(unsigned long long a, unsigned long long b, int choice) {
        unsigned long long one = 1;
        return (~((unsigned long long) choice - one) & a) | ((unsigned long long) (choice - one) & b);
    }

    static void conditional_assign(unsigned long long* src, unsigned long long* dst, int choice) {
        unsigned long long mask = -((long long) choice);
        *src = *src ^ ((mask) & (*src ^ *dst));
    }

    static void conditional_assign(int* src, int* dst, int choice) {
        unsigned int mask = -((int) choice);
        *src = *src ^ ((mask) & (*src ^ *dst));
    }

    /**
     * constant time selector
     * @param a
     * @param b
     * @param choice 0 or 1
     * @return choice = 1 -> a , choice = 0 -> return b
     */
    static unsigned __int128 conditional_select(unsigned __int128 a, unsigned __int128 b, int choice) {
        unsigned __int128 one = 1;
        return (~((unsigned __int128) choice - one) & a) | ((unsigned __int128) (choice - one) & b);
    }

    /**
     * constant time selector
     * @param a
     * @param b
     * @param choice 0 or 1
     * @return choice = 1 -> a , choice = 0 -> return b
     */
    static byte_t conditional_select(byte_t a, byte_t b, int choice) {
        byte_t one = 1;
        return (~((byte_t) choice - one) & a) | ((byte_t) (choice - one) & b);
    }

    /**
     * constant time selector
     * @param a
     * @param b
     * @param choice 0 or 1
     * @return choice = 1 -> a , choice = 0 -> return b
     */
    static void conditional_swap(Node* a, Node* b, int choice) {
        Node tmp = *b;
        Node::conditional_swap(a->index, b->index, choice);
        Node::conditional_swap(a->pos, b->pos, choice);
        Node::conditional_swap(a->value, b->value, choice);
        Node::conditional_swap(a->isDummy, b->isDummy, choice);
        Node::conditional_swap(a->evictionNode, b->evictionNode, choice);
        for (int k = 0; k < b->dum.size(); k++) {
            Node::conditional_swap(a->dum[k], b->dum[k], choice);
        }

        //        b->index = Node::conditional_select((long long) a->index, (long long) b->index, choice);
        //        b->isDummy = Node::conditional_select(a->isDummy, b->isDummy, choice);
        //        b->pos = Node::conditional_select((long long) a->pos, (long long) b->pos, choice);
        //        b->value = Node::conditional_select((long long) a->value, (long long) b->value, choice);
        //                for (int k = 0; k < b->dum.size(); k++) {
        //                    b->dum[k] = Node::conditional_select(a->dum[k], b->dum[k], choice);
        //                }
        //        b->evictionNode = Node::conditional_select(a->evictionNode, b->evictionNode, choice);
        //        a->index = Node::conditional_select((long long) tmp.index, (long long) a->index, choice);
        //        a->isDummy = Node::conditional_select(tmp.isDummy, a->isDummy, choice);
        //        a->pos = Node::conditional_select((long long) tmp.pos, (long long) a->pos, choice);
        //        a->value = Node::conditional_select((long long) tmp.value, (long long) a->value, choice);
        //                for (int k = 0; k < b->dum.size(); k++) {
        //                    a->dum[k] = Node::conditional_select(tmp.dum[k], a->dum[k], choice);
        //                }
        //        a->evictionNode = Node::conditional_select(tmp.evictionNode, a->evictionNode, choice);
    }

    /**
     * constant time selector
     * @param a
     * @param b
     * @param choice 0 or 1
     * @return choice = 1 -> a , choice = 0 -> return b
     */
    static void conditional_swap(BlockInfo* a, BlockInfo* b, int choice) {
        BlockInfo tmp = *b;
        b->i = Node::conditional_select((long long) a->i, (long long) b->i, choice);
        b->pos = Node::conditional_select(a->pos, b->pos, choice);
        b->isInBucket = Node::conditional_select((long long) a->isInBucket, (long long) b->isInBucket, choice);
        a->i = Node::conditional_select((long long) tmp.i, (long long) a->i, choice);
        a->pos = Node::conditional_select(tmp.pos, a->pos, choice);
        a->isInBucket = Node::conditional_select((long long) tmp.isInBucket, (long long) a->isInBucket, choice);
    }

    static void conditional_swap(unsigned long long& a, unsigned long long& b, int choice) {
        //        unsigned long long tmp = b;
        //        b = Node::conditional_select((long long) a, (long long) b, choice);
        //        a = Node::conditional_select((long long) tmp, (long long) a, choice);
        unsigned long long mask = -((int) choice);
        unsigned long long t = mask & (a ^ b);
        a ^= t;
        b ^= t;
    }

    static void conditional_swap(long long& a, long long& b, int choice) {
        //        unsigned long long tmp = b;
        //        b = Node::conditional_select((long long) a, (long long) b, choice);
        //        a = Node::conditional_select((long long) tmp, (long long) a, choice);
        long long mask = -((int) choice);
        long long t = mask & (a ^ b);
        a ^= t;
        b ^= t;
    }

    static void conditional_swap(byte_t& a, byte_t& b, int choice) {
        //        unsigned long long tmp = b;
        //        b = Node::conditional_select((long long) a, (long long) b, choice);
        //        a = Node::conditional_select((long long) tmp, (long long) a, choice);
        byte_t mask = -((int) choice);
        byte_t t = mask & (a ^ b);
        a ^= t;
        b ^= t;
    }

    static void conditional_swap(bool& a, bool& b, int choice) {
        //        unsigned long long tmp = b;
        //        b = Node::conditional_select((long long) a, (long long) b, choice);
        //        a = Node::conditional_select((long long) tmp, (long long) a, choice);
        char mask = -((int) choice);
        char t = mask & (a ^ b);
        a ^= t;
        b ^= t;
    }

    /**
     * constant time selector
     * @param a
     * @param b
     * @param choice 0 or 1
     * @return choice = 1 -> a , choice = 0 -> return b
     */
    static int conditional_select(int a, int b, int choice) {
        unsigned int one = 1;
        return (~((unsigned int) choice - one) & a) | ((unsigned int) (choice - one) & b);
    }

    static bool CTeq(int a, int b) {
        return !(a^b);
    }

    static bool CTeq(long long a, long long b) {
        return !(a^b);
    }

    static bool CTeq(unsigned __int128 a, unsigned __int128 b) {
        return !(a^b);
    }

    static bool CTeq(unsigned long long a, unsigned long long b) {
        return !(a^b);
    }

    /**
     * constant time selector
     * @param a
     * @param b
     * @param choice 0 or 1
     * @return choice = 1 -> a into b
     */
    static void conditional_assign(Node* dst, Node* src, int choice) {
        dst->index = Node::conditional_select((long long) src->index, (long long) dst->index, choice);
        dst->isDummy = Node::conditional_select(src->isDummy, dst->isDummy, choice);
        dst->pos = Node::conditional_select((long long) src->pos, (long long) dst->pos, choice);
        dst->value = Node::conditional_select((long long) src->value, (long long) dst->value, choice);
        for (int k = 0; k < dst->dum.size(); k++) {
            dst->dum[k] = Node::conditional_select(src->dum[k], dst->dum[k], choice);
        }
        dst->evictionNode = Node::conditional_select(src->evictionNode, dst->evictionNode, choice);
    }

    static void conditional_assign(byte_t* src, byte_t* dst, int choice) {
        byte_t mask = -((int) choice);
        *src = *src ^ ((mask) & (*src ^ *dst));
    }
};


using BucketBytes = std::array<byte_t, sizeof (Node) * Z >;


#endif /* NODE_H */


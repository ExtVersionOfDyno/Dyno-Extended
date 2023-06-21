#include "ObliviousOperations.h"

ObliviousOperations::ObliviousOperations() {
}

ObliviousOperations::~ObliviousOperations() {
}

void ObliviousOperations::oblixmergesort(Node*** data, int size) {
    if (size == 0 || size == 1) {
        return;
    }
    int len = size;
    int t = ceil(log2(len));
    long long p = 1 << (t - 1);

    while (p > 0) {
        long long q = 1 << (t - 1);
        long long r = 0;
        long long d = p;

        while (d > 0) {
            long long i = 0;
            while (i < len - d) {
                if ((i & p) == r) {
                    long long j = i + d;
                    if (i != j) {
                        int node_cmp = Node::CTcmp((*data)[j]->evictionNode, (*data)[i]->evictionNode);
                        int dummy_blocks_last = Node::CTcmp((*data)[i]->isDummy, (*data)[j]->isDummy);
                        int same_nodes = Node::CTeq(node_cmp, 0);
                        bool cond = Node::CTeq(Node::conditional_select(dummy_blocks_last, node_cmp, same_nodes), -1);
                        Node::conditional_swap((*data)[i], (*data)[j], cond);
                    }
                }
                i += 1;
            }
            d = q - p;
            q /= 2;
            r = p;
        }
        p /= 2;
    }

    for (int low = 0, high = size - 1; low < high; low++, high--) {
        std::swap((*data)[low], (*data)[high]);
    }
}

void ObliviousOperations::bitonicSort(vector<BlockInfo*>* nodes, bool firstSort) {
    int len = nodes->size();
    bitonic_sort(nodes, 0, len, 1, firstSort);
}

void ObliviousOperations::bitonic_sort(vector<BlockInfo*>* nodes, int low, int n, int dir, bool firstSort) {
    if (n > 1) {
        int middle = n / 2;
        bitonic_sort(nodes, low, middle, !dir, firstSort);
        bitonic_sort(nodes, low + middle, n - middle, dir, firstSort);
        bitonic_merge(nodes, low, n, dir, firstSort);
    }
}

void ObliviousOperations::bitonic_merge(vector<BlockInfo*>* nodes, int low, int n, int dir, bool firstSort) {
    if (n > 1) {
        int m = greatest_power_of_two_less_than(n);

        for (int i = low; i < (low + n - m); i++) {
            if (i != (i + m)) {
                if (firstSort) {
                    compare_and_swap1((*nodes)[i], (*nodes)[i + m], dir);
                } else {
                    compare_and_swap2((*nodes)[i], (*nodes)[i + m], dir);
                }
            }
        }

        bitonic_merge(nodes, low, m, dir, firstSort);
        bitonic_merge(nodes, low + m, n - m, dir, firstSort);
    }
}

void ObliviousOperations::compare_and_swap1(BlockInfo* item_i, BlockInfo* item_j, int dir) {
    int node_compare = Node::CTcmp(item_i->pos, item_j->pos);
    int dummy_compare = Node::CTcmp(item_i->i, item_j->i);
    int res = Node::conditional_select(node_compare, dummy_compare, !Node::CTeq(node_compare, 0));
    int cmp = Node::CTeq(res, 1);
    Node::conditional_swap(item_i, item_j, Node::CTeq(cmp, dir));
}

void ObliviousOperations::compare_and_swap2(BlockInfo* item_i, BlockInfo* item_j, int dir) {
    int first_in_bucket = Node::CTcmp(item_i->isInBucket, 0);
    int is_in_bucket_compare = Node::CTcmp(item_i->isInBucket, item_j->isInBucket);
    int node_compare = Node::CTcmp(item_i->pos, item_j->pos);
    int dummy_compare = Node::CTcmp(item_i->i, item_j->i);
    int res0 = Node::conditional_select(node_compare, dummy_compare, first_in_bucket);
    int res = Node::conditional_select(is_in_bucket_compare, res0, !Node::CTeq(is_in_bucket_compare, 0));
    int cmp = Node::CTeq(res, 1);
    Node::conditional_swap(item_i, item_j, Node::CTeq(cmp, dir));
}

int ObliviousOperations::greatest_power_of_two_less_than(int n) {
    int k = 1;
    while (k > 0 && k < n) {
        k = k << 1;
    }
    return k >> 1;
}

void ObliviousOperations::bitonicSort(vector<pair<unsigned long long, unsigned long long> >* nodes) {
    int len = nodes->size();
    bitonic_sort(nodes, 0, len, 1);
}

void ObliviousOperations::bitonic_sort(vector<pair<unsigned long long, unsigned long long> >* nodes, int low, int n, int dir) {
    if (n > 1) {
        int middle = n / 2;
        bitonic_sort(nodes, low, middle, !dir);
        bitonic_sort(nodes, low + middle, n - middle, dir);
        bitonic_merge(nodes, low, n, dir);
    }
}

void ObliviousOperations::bitonic_merge(vector<pair<unsigned long long, unsigned long long> >* nodes, int low, int n, int dir) {
    if (n > 1) {
        int m = greatest_power_of_two_less_than(n);

        for (int i = low; i < (low + n - m); i++) {
            if (i != (i + m)) {
                compare_and_swap((*nodes)[i], (*nodes)[i + m], dir);
            }
        }

        bitonic_merge(nodes, low, m, dir);
        bitonic_merge(nodes, low + m, n - m, dir);
    }
}

void ObliviousOperations::compare_and_swap(pair<unsigned long long, unsigned long long>& item_i, pair<unsigned long long, unsigned long long>& item_j, int dir) {
    int node_compare = Node::CTcmp(item_i.first, item_j.first);
    int cmp = Node::CTeq(node_compare, 1);
    int choice = Node::CTeq(cmp, dir);

    pair<unsigned long long, unsigned long long> tmp = item_j;
    item_j.first = Node::conditional_select((long long) item_i.first, (long long) item_j.first, choice);
    item_j.second = Node::conditional_select((long long) item_i.second, (long long) item_j.second, choice);
    item_i.first = Node::conditional_select((long long) tmp.first, (long long) item_i.first, choice);
    item_i.second = Node::conditional_select(tmp.second, item_i.second, choice);
}

void ObliviousOperations::bitonicSort(vector<pair<unsigned long long, Node*> >* nodes) {
    int len = nodes->size();
    bitonic_sort(nodes, 0, len, 1);
}

void ObliviousOperations::bitonic_sort(vector<pair<unsigned long long, Node*> >* nodes, int low, int n, int dir) {
    if (n > 1) {
        int middle = n / 2;
        bitonic_sort(nodes, low, middle, !dir);
        bitonic_sort(nodes, low + middle, n - middle, dir);
        bitonic_merge(nodes, low, n, dir);
    }
}

void ObliviousOperations::bitonic_merge(vector<pair<unsigned long long, Node*> >* nodes, int low, int n, int dir) {
    if (n > 1) {
        int m = greatest_power_of_two_less_than(n);

        for (int i = low; i < (low + n - m); i++) {
            if (i != (i + m)) {
                compare_and_swap((*nodes)[i], (*nodes)[i + m], dir);
            }
        }

        bitonic_merge(nodes, low, m, dir);
        bitonic_merge(nodes, low + m, n - m, dir);
    }
}

void ObliviousOperations::compare_and_swap(pair<unsigned long long, Node*>& item_i, pair<unsigned long long, Node*>& item_j, int dir) {
    int node_compare = Node::CTcmp(item_j.first, item_i.first);
    int dummy_compare = Node::CTcmp(item_i.second->isDummy, item_j.second->isDummy);
    int res = Node::conditional_select(node_compare, dummy_compare, !Node::CTeq(node_compare, 0));
    int cmp = Node::CTeq(res, 1);
    Node::conditional_swap(item_i.second, item_j.second, Node::CTeq(cmp, dir));
    Node::conditional_swap(item_i.first, item_j.first, Node::CTeq(cmp, dir));

}
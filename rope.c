#include "./rope.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#define EMPTY ""

char *strdup(const char *s);

RopeNode* makeRopeNode(const char* str) {
    RopeNode* node_tree = malloc(sizeof(RopeNode));

    if (!node_tree) {
        return NULL;
    }

    node_tree->str = str;
    node_tree->weight = strlen(str);
    node_tree->left = node_tree->right = NULL;

    return node_tree;
}

RopeTree* makeRopeTree(RopeNode* root) {
    RopeTree* new_tree = malloc(sizeof(RopeTree));

    if (!new_tree) {
        return NULL;
    }

    new_tree->root = root;

    return new_tree;
}

void printRopeNode(RopeNode* rn) {
    if (!rn)
        return;

    if (!(rn->left) && !(rn->right)) {
        printf("%s", rn->str);
        return;
    }

    printRopeNode(rn->left);
    printRopeNode(rn->right);
}

void printRopeTree(RopeTree* rt) {
    if (rt && rt->root) {
        printRopeNode(rt->root);
        printf("%s", "\n");
    }
}

void debugRopeNode(RopeNode* rn, int indent) {
    if (!rn)
        return;

    for (int i = 0; i < indent; ++i)
        printf("%s", " ");

    if (!strcmp(rn->str, EMPTY))
        printf("# %d\n", rn->weight);
    else
        printf("%s %d\n", rn->str, rn->weight);

    debugRopeNode(rn->left, indent+2);
    debugRopeNode(rn->right, indent+2);
}

int getTotalWeight(RopeNode* rt) {
    if (!rt)
        return 0;

    return rt->weight + getTotalWeight(rt->right);
}

RopeTree* concat(RopeTree* rt1, RopeTree* rt2) {
    if (!rt1){
        return rt2;
    }
    if (!rt2){
        return rt1;
    }
    RopeNode* root = makeRopeNode((char *)strdup(EMPTY));
    RopeTree* rope_concat = makeRopeTree(root);

    rope_concat->root->weight = getTotalWeight(rt1->root);

    rope_concat->root->left = rt1->root;
    rope_concat->root->right = rt2->root;

    return rope_concat;
}

char __index__(RopeNode* node, int idx)
{
    if (!node) {
        return 0;
    }
    if (node->weight <= idx && node->right) {
        return __index__(node->right, idx - node->weight);
    }
    if (node->left) {
        return __index__(node->left, idx);
    }
    return node->str[idx];
}

char indexRope(RopeTree* rt, int idx) {
    if (!rt->root){
        return 0;
    }
    return __index__(rt->root, idx);
}


char* search(RopeTree* rt, int start, int end) {
    int size = end - start + 1;
    int count = 0;
    int idx_search = start;

    char* search_word = calloc(size, 1);

    if (!search_word) {
        return 0;
    }

    while (size != 1) {
        search_word[count] = indexRope(rt, idx_search);
        ++idx_search;
        ++count;
        --size;
    }
    return search_word;
}

void free_node(RopeNode* node)
{
    if (!node) {
        return;
    }

    free((void*)node->str);
    free_node(node->left);
    free_node(node->right);
    free(node);
}

void free_tree(RopeTree* tree)
{
    free_node(tree->root);
    free(tree);
}

void __split__(RopeNode *node, int idx, RopeTree **left_tree,
                RopeTree **right_tree) {
    if (!node) {
        return;
    }

    int size = (int)strlen(node->str);

    if (idx == 0 && size) {
        RopeTree *new_tree = makeRopeTree(makeRopeNode((char *)
                                        strdup(node->str)));
        RopeTree* fake_tree =  *right_tree;

        *right_tree = concat(fake_tree, new_tree);

        free(fake_tree);
        free(new_tree);
        return;
    }

    if (size > idx) {
        int i = 0;
        char *left, *right;

        left = calloc(idx + 1, 1);
        right = calloc(node->weight - idx + 1, 1);

        if (!left || !right) {
            return;
        }

        while (i < node->weight) {
            if (i < idx) {
                left[i] = node->str[i];
            } else {
                right[i - idx] = node->str[i];
            }
            ++i;
        }

        RopeNode *right_node = makeRopeNode(right);
        RopeNode *left_node = makeRopeNode(left);

        RopeTree *new_right = makeRopeTree(right_node);
        RopeTree *new_left = makeRopeTree(left_node);

        RopeTree* fake_right =  *right_tree;
        RopeTree* fake_left =  *left_tree;

        *right_tree = concat(new_right, fake_right);

        *left_tree = concat(fake_left, new_left);

        free(new_right);
        free(new_left);
        free(fake_left);
        free(fake_right);
        return;
    }

    if (size) {
        RopeTree *new_tree = makeRopeTree(makeRopeNode(
                                (char *)strdup(node->str)));
        RopeTree* fake_tree =  *left_tree;

        *left_tree = concat(fake_tree, new_tree);

        free(fake_tree);
        free(new_tree);
        return;
    }

    __split__(node->left, idx, left_tree, right_tree);

    if (idx - node->weight < 0) {
        idx = 0;
    } else {
        idx = idx - node->weight;
    }

    __split__(node->right, idx, left_tree, right_tree);
}

SplitPair split(RopeTree* rt, int idx) {
    SplitPair split_pair;

    RopeTree *right_tree = makeRopeTree(makeRopeNode((char *)strdup(EMPTY)));
    RopeTree *left_tree = makeRopeTree(makeRopeNode((char *)strdup(EMPTY)));

    __split__(rt->root, idx, &left_tree, &right_tree);

    split_pair.right = right_tree->root;
    split_pair.left = left_tree->root;

    free(right_tree);
    free(left_tree);

    return split_pair;
}

RopeTree* insert(RopeTree* rt, int idx, const char* str) {
    SplitPair split_tree = split(rt, idx);
    RopeTree *tree_left, *tree_mid, *tree_right, *new_tree, *tree;

    tree_left = makeRopeTree(split_tree.left);
    tree_right = makeRopeTree(split_tree.right);

    tree_mid = makeRopeTree(makeRopeNode(str));

    tree = concat(tree_left, tree_mid);
    new_tree = concat(tree, tree_right);

    free(tree_right);
    free(tree_left);
    free(tree_mid);
    free(tree);

    return new_tree;
}

RopeTree* delete(RopeTree* rt, int start, int len) {
    SplitPair split1, split2;

    split1 = split(rt, start);

    RopeTree* tree1 = makeRopeTree(split1.left);
    RopeTree* tree2 = makeRopeTree(split1.right);

    split2 = split(tree2, len);

    RopeTree* tree3 = makeRopeTree(split2.left);
    RopeTree* tree4 = makeRopeTree(split2.right);

    RopeTree* concat_tree = concat(tree1, tree4);

    free(tree1);
    free_tree(tree2);
    free_tree(tree3);
    free(tree4);

    return concat_tree;
}

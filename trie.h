#ifndef TRIE_H_
#define TRIE_H_

#include <stdio.h>
#include <arpa/inet.h>

 typedef struct node_t
    {
        struct _node_t *left;
        struct _node_t *right;
        /** Network ID (value) */
        int index;
        /** Indicator: is as loaded? (not empty) */
        bool has_network;
 }node_t;

typedef struct trie_t{
    node_t root;
}trie_t


#endif
/*************************************************************************
	> File Name: imap.h
	> Author:
	> Mail:
	> Created Time: Mon 14 Dec 2020 10:23:02 AM CST
    > Description: Header file for main program of IMap
 ************************************************************************/

#ifndef _IMAP_H
#define _IMAP_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <time.h>
#include <math.h>

#define ARRLEN(arr) sizeof(arr)/sizeof(arr[0])

// PRIME_LIST[i] is the smallest prime greater than 2 ^ i
const uint32_t PRIME_LIST [] = {
//  1, 2, 4,  8, 16, 32, 64, 128, ( 2 ^ i)
    2, 3, 5, 11, 17, 37, 67, 131,
//  256, 512, 1024, 2048, 4096, 8192, 16384, 32768,
    257, 521, 1031, 2053, 4099, 8209, 16411, 32771,
//  65536, 131072, 262144, 524288, 1048576, 2097152, 4194304, 8388608,
    65537, 131101, 262147, 524309, 1048583, 2097169, 4194319, 8388617,
//  16777216, 33554432, 67108864, 134217728, 268435456, 536870912
    16777259, 33554467, 67108879, 134217757, 268435459, 536870923
};

#endif

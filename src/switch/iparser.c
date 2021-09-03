/*************************************************************************
	> File Name: iparser.c
	> Author: Cheng Guo
	> Mail: aeromarisa@gmail.com
	> Created Time: Tue 29 Jun 2021 13:47:02 PM CST
    > Description: Config file parser for IMap
 ************************************************************************/

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "iswitch.h"

static int ip_space_list_parse(FILE *fd, long start_fptr,
                                probe_entry_t **probe_ip_space,
                                uint32_t *probe_ip_space_count) {
    char token1[256];
    char token2[256];
    *probe_ip_space_count = 0;

    fscanf(fd, "%s %s", token1, token2);
    if (strcmp(token1, "=") != 0 || strcmp(token2, "{") != 0) {
        printf("Invalid var defination format.\n");
        return 1;
    }
    fscanf(fd, "%s", token1);
    while (1) {
        if (strcmp(token1, "}") != 0) {
            fscanf(fd, "%s %s", token2, token1);
            *probe_ip_space_count += 1;
        }
        else {
            // Go to start position of this var, and scan again
            fseek(fd, start_fptr, SEEK_SET);
            break;
        }
    }
    *probe_ip_space = (probe_entry_t *)malloc(*probe_ip_space_count * 
                                               sizeof(probe_entry_t));
    fscanf(fd, "%s %s", token1, token2);
    for (int entry_idx = 0; entry_idx < *probe_ip_space_count; entry_idx ++) {
        fscanf(fd, "%s %s", token1, token2);
        (*probe_ip_space)[entry_idx].start = htonl(inet_addr(token1));
        (*probe_ip_space)[entry_idx].end = htonl(inet_addr(token2));
    }
    fscanf(fd, "%s", token1);

    return 0;
}

void config_file_parse(const char *config_filename, 
                       probe_entry_t **probe_ip_space,
                       uint32_t *probe_ip_space_count) {
    FILE *fd;

    printf("Start reading config file.\n");
    fd = fopen(config_filename, "r");
    if (fd == NULL) {
        // Error when opening config file
        printf("Error when opening config file!\n");
        exit(0);
    }

    char var_name[256];
    long start_fptr;
    int status;
    while (!feof(fd)) {
        fscanf(fd, "%s", var_name);
        if (feof(fd)) break;
        // Record start position of this config item
        start_fptr = ftell(fd);

        if (strcmp(var_name, "ip_space_list") == 0) {
            // Parse ip space list
            status = ip_space_list_parse(fd, start_fptr, 
                                         probe_ip_space, 
                                         probe_ip_space_count);
        }
        else {
            printf("Unrecognized config item: %s\n", var_name);
        }
        if (status != 0) {
            printf("Error when opening config file!\n");
            exit(0);
        }
    }
    fclose(fd);
    printf("Config file read done.\n");
}
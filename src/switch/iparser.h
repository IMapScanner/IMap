/*************************************************************************
	> File Name: iparser.h
	> Author: Cheng Guo
	> Mail: aeromarisa@gmail.com
	> Created Time: Tue 29 Jun 2021 13:47:02 PM CST
    > Description: Config file parser for IMap
 ************************************************************************/

#ifndef _IPARSER_H
#define _IPARSER_H

static void ip_space_list_parse(FILE *fd, long start_fptr,
                                probe_entry_t **probe_ip_space,
                                uint32_t *probe_ip_space_count);

void config_file_parse(const char *config_filename, 
                       probe_entry_t **probe_ip_space,
                       uint32_t *probe_ip_space_count);

#endif
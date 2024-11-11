/***************************************************************************
 *   Copyright (C) 2024 by Simon labrecque                                 *
 *   Author Simon Labrecque  simon@wegel.ca                                *
 *                                                                         *
 * This software is available under either the Mozilla Public License      *
 * version 2.0 or the GNU LGPL version 2 (or later) license, whichever     *
 * you choose.                                                             *
 *                                                                         *
 * MPL 2.0:                                                                *
 *                                                                         *
 *   This Source Code Form is subject to the terms of the Mozilla Public   *
 *   License, v. 2.0. If a copy of the MPL was not distributed with this   *
 *   file, You can obtain one at http://mozilla.org/MPL/2.0/.              *
 *                                                                         *
 *                                                                         *
 * LGPL 2:                                                                 *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU Library General Public License as       *
 *   published by the Free Software Foundation; either version 2 of the    *
 *   License, or (at your option) any later version.                       *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU Library General Public     *
 *   License along with this program; if not, write to the                 *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../lib/libplctag.h"
#include "utils.h"

#define REQUIRED_VERSION 2,1,0
#define TAG_STRING_TEMPLATE "protocol=ab_eip&gateway=%s&path=%s&plc=controllogix&elem_count=1&name=%s"
#define DEFAULT_TIMEOUT 5000
#define DEFAULT_NUM_INDEXES 3
#define MAX_NUM_INDEXES 100

static void usage(void)
{
    fprintf(stderr, "Usage: sequential_write_test <PLC IP> <PLC path> <tag name> <count> [timeout]\n"
           "  <PLC IP>   - IP address or hostname of the PLC\n"
           "  <PLC path> - Path to the PLC (e.g. '1,0')\n"
           "  <tag name> - Name of the array tag to test\n"
           "  <count>    - Number of array indexes to test (1-%d)\n"
           "  [timeout]  - Timeout in milliseconds (default %d)\n"
           "\nExample: sequential_write_test 192.168.1.10 1,0 MyTag 5 2000\n",
           MAX_NUM_INDEXES, DEFAULT_TIMEOUT);
    exit(1);
}

static char *setup_tag_string(const char *gateway, const char *path, const char *tag_name, int index)
{
    char *tag_string = (char *)calloc(1, 256);
    char full_tag_name[128];

    if(!tag_string) {
        fprintf(stderr, "ERROR: Memory allocation failed!\n");
        exit(1);
    }

    if(strlen(gateway) == 0 || strlen(path) == 0 || strlen(tag_name) == 0) {
        fprintf(stderr, "ERROR: Gateway IP, PLC path, and tag name must not be empty!\n");
        free(tag_string);
        usage();
    }

    /* create tag name with array index */
    snprintf(full_tag_name, sizeof(full_tag_name), "%s[%d]", tag_name, index);

    /* create full connection string */
    snprintf(tag_string, 256, TAG_STRING_TEMPLATE, gateway, path, full_tag_name);
    return tag_string;
}

static int write_value(const char *gateway, const char *path, const char *tag_name, int index, float value, int timeout)
{
    char *tag_string;
    int32_t tag;
    int rc;

    /* create the tag path with the array index */
    tag_string = setup_tag_string(gateway, path, tag_name, index);

    if(!tag_string) {
        return PLCTAG_ERR_NO_MEM;
    }

    /* create the tag */
    tag = plc_tag_create(tag_string, timeout);
    free(tag_string);

    if(tag < 0) {
        fprintf(stderr, "ERROR creating tag for index %d: %s\n",
                index, plc_tag_decode_error(tag));
        return tag;
    }

    /* make sure tag is ready */
    rc = plc_tag_status(tag);
    if(rc != PLCTAG_STATUS_OK) {
        fprintf(stderr, "ERROR setting up tag for index %d: %s\n",
                index, plc_tag_decode_error(rc));
        plc_tag_destroy(tag);
        return rc;
    }

    /* write the value */
    plc_tag_set_float32(tag, 0, value);
    rc = plc_tag_write(tag, timeout);

    if(rc != PLCTAG_STATUS_OK) {
        fprintf(stderr, "ERROR writing value %.1f to index %d: %s\n",
                value, index, plc_tag_decode_error(rc));
        plc_tag_destroy(tag);
        return rc;
    }

    fprintf(stderr, "Wrote %.1f to index %d\n", value, index);
    plc_tag_destroy(tag);
    return PLCTAG_STATUS_OK;
}

static float read_value(const char *gateway, const char *path, const char *tag_name, int index, int timeout, int *status)
{
    char *tag_string;
    int32_t tag;
    int rc;
    float result = 0.0f;

    /* create the tag path with the array index */
    tag_string = setup_tag_string(gateway, path, tag_name, index);
    if(!tag_string) {
        *status = PLCTAG_ERR_NO_MEM;
        return result;
    }

    /* create the tag */
    tag = plc_tag_create(tag_string, timeout);
    free(tag_string);

    if(tag < 0) {
        fprintf(stderr, "ERROR creating tag for index %d: %s\n",
                index, plc_tag_decode_error(tag));
        *status = tag;
        return result;
    }

    /* read the data */
    rc = plc_tag_read(tag, timeout);
    if(rc != PLCTAG_STATUS_OK) {
        fprintf(stderr, "ERROR reading value at index %d: %s\n",
                index, plc_tag_decode_error(rc));
        plc_tag_destroy(tag);
        *status = rc;
        return result;
    }

    result = plc_tag_get_float32(tag, 0);
    fprintf(stderr, "Read %.1f from index %d\n", result, index);

    plc_tag_destroy(tag);
    *status = PLCTAG_STATUS_OK;
    return result;
}

int main(int argc, char **argv)
{
    int timeout = DEFAULT_TIMEOUT;
    int num_indexes;
    int rc = PLCTAG_STATUS_OK;
    float *test_values;
    int all_passed = 1;
    int i;

    if(argc < 5) {
        usage();
    }

    /* check the library version */
    if(plc_tag_check_lib_version(REQUIRED_VERSION) != PLCTAG_STATUS_OK) {
        fprintf(stderr, "ERROR: Required library version %d.%d.%d not available!\n", REQUIRED_VERSION);
        return 1;
    }

    const char *gateway = argv[1];
    const char *path = argv[2];
    const char *tag_name = argv[3];

    /* get number of indexes to test */
    num_indexes = atoi(argv[4]);
    if(num_indexes <= 0 || num_indexes > MAX_NUM_INDEXES) {
        fprintf(stderr, "ERROR: Number of indexes must be between 1 and %d!\n", MAX_NUM_INDEXES);
        usage();
    }

    /* get optional timeout parameter */
    if(argc > 5) {
        timeout = atoi(argv[5]);
        if(timeout <= 0) {
            fprintf(stderr, "ERROR: Timeout must be a positive integer!\n");
            usage();
        }
    }

    /* allocate test values array */
    test_values = (float *)calloc((size_t)num_indexes, sizeof(float));
    if(!test_values) {
        fprintf(stderr, "ERROR: Failed to allocate memory for test values!\n");
        return 1;
    }

    /* initialize test values */
    for(i = 0; i < num_indexes; i++) {
        test_values[i] = 11.0f + (float)i * 11.5f;
    }

    fprintf(stderr, "Writing values to tag %s (%d indexes)...\n", tag_name, num_indexes);

    /* write values sequentially */
    for(i = 0; i < num_indexes; i++) {
        rc = write_value(gateway, path, tag_name, i, test_values[i], timeout);
        if(rc != PLCTAG_STATUS_OK) {
            fprintf(stderr, "Failed to write to index %d\n", i);
            all_passed = 0;
            goto cleanup;
        }
    }

    /* small delay to ensure writes complete */
    util_sleep_ms(100);

    /* read back and verify all values */
    fprintf(stderr, "\nReading back all values...\n");
    for(i = 0; i < num_indexes; i++) {
        int read_status;
        float read_result = read_value(gateway, path, tag_name, i, timeout, &read_status);

        if(read_status != PLCTAG_STATUS_OK) {
            all_passed = 0;
            continue;
        }

        if(read_result != test_values[i]) {
            fprintf(stderr, "ERROR: Mismatch at index %d: wrote %.1f, read %.1f\n",
                   i, test_values[i], read_result);
            all_passed = 0;
        } else {
            fprintf(stderr, "Values match for index %d\n", i);
        }
    }

cleanup:
    free(test_values);

    fprintf(stderr, "\nTest %s\n", all_passed ? "PASSED" : "FAILED");
    return all_passed ? 0 : 1;
}

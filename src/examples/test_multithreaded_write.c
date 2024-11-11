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

#if defined(WIN32) || defined(_WIN32)
#include <Windows.h>
#define THREAD_HANDLE HANDLE
#define THREAD_RET DWORD WINAPI
#define THREAD_PARAM LPVOID
#else
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#define THREAD_HANDLE pthread_t
#define THREAD_RET void*
#define THREAD_PARAM void*
#endif

#define REQUIRED_VERSION 2,1,0
#define TAG_STRING_TEMPLATE "protocol=ab_eip&gateway=%s&path=%s&plc=controllogix&elem_count=1&name=%s"
#define DEFAULT_TIMEOUT 5000
#define DEFAULT_NUM_INDEXES 3
#define MAX_NUM_INDEXES 100

/* synchronization primitives */
#if defined(WIN32) || defined(_WIN32)
static HANDLE start_event;
#else
static pthread_mutex_t start_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t start_cond = PTHREAD_COND_INITIALIZER;
static volatile int start_flag = 0;
#endif

struct write_args {
    char *base_path;
    int index;
    float value;
    int success;
};

static void usage(void)
{
    fprintf(stderr, "Usage: test_multithreaded_write <PLC IP> <PLC path> <tag name> <count> [timeout]\n"
           "  <PLC IP>   - IP address or hostname of the PLC\n"
           "  <PLC path> - Path to the PLC (e.g. '1,0')\n"
           "  <tag name> - Name of the array tag to test\n"
           "  <count>    - Number of array indexes to test (1-%d)\n"
           "  [timeout]  - Timeout in milliseconds (default %d)\n"
           "\nExample: test_multithreaded_write 192.168.1.10 1,0 MyTag 5 2000\n",
           MAX_NUM_INDEXES, DEFAULT_TIMEOUT);
    exit(1);
}

static void sleep_ms(int milliseconds)
{
#if defined(WIN32) || defined(_WIN32)
    Sleep(milliseconds);
#else
    usleep(milliseconds * 1000);
#endif
}

static char *setup_tag_string(const char *gateway, const char *path, const char *tag_name)
{
    char *tag_string = (char *)calloc(1, 256);
    if(!tag_string) {
        fprintf(stderr, "ERROR: Memory allocation failed!\n");
        exit(1);
    }

    if(strlen(gateway) == 0 || strlen(path) == 0 || strlen(tag_name) == 0) {
        fprintf(stderr, "ERROR: Gateway IP, PLC path, and tag name must not be empty!\n");
        free(tag_string);
        usage();
    }

    snprintf(tag_string, 256, TAG_STRING_TEMPLATE, gateway, path, tag_name);
    return tag_string;
}

THREAD_RET write_thread_func(THREAD_PARAM arg)
{
    struct write_args *args = (struct write_args *)arg;
    char tag_path[256];

    /* wait for start signal */
#if defined(WIN32) || defined(_WIN32)
    WaitForSingleObject(start_event, INFINITE);
#else
    pthread_mutex_lock(&start_mutex);
    while(!start_flag) {
        pthread_cond_wait(&start_cond, &start_mutex);
    }
    pthread_mutex_unlock(&start_mutex);
#endif

    snprintf(tag_path, sizeof(tag_path), "%s[%d]", args->base_path, args->index);

    int32_t tag = plc_tag_create(tag_path, DEFAULT_TIMEOUT);
    if(tag < 0) {
        fprintf(stderr, "Thread %d: ERROR creating tag %s: %s\n",
               args->index, tag_path, plc_tag_decode_error(tag));
        args->success = 0;
        return 0;
    }

    int rc = plc_tag_status(tag);
    if(rc != PLCTAG_STATUS_OK) {
        fprintf(stderr, "Thread %d: ERROR setting up tag %s: %s\n",
               args->index, tag_path, plc_tag_decode_error(rc));
        plc_tag_destroy(tag);
        args->success = 0;
        return 0;
    }

    plc_tag_set_float32(tag, 0, args->value);
    rc = plc_tag_write(tag, DEFAULT_TIMEOUT);

    if(rc != PLCTAG_STATUS_OK) {
        fprintf(stderr, "Thread %d: Write failed for %s: %s\n",
               args->index, tag_path, plc_tag_decode_error(rc));
        plc_tag_destroy(tag);
        args->success = 0;
        return 0;
    }

    fprintf(stderr, "Thread %d: Wrote %.1f to %s\n", args->index, args->value, tag_path);
    plc_tag_destroy(tag);
    args->success = 1;
    return 0;
}

float read_array_index(const char *base_path, int index, int *success)
{
    char tag_path[256];
    snprintf(tag_path, sizeof(tag_path), "%s[%d]", base_path, index);

    int32_t tag = plc_tag_create(tag_path, DEFAULT_TIMEOUT);
    if(tag < 0) {
        fprintf(stderr, "ERROR creating read tag %s: %s\n", tag_path, plc_tag_decode_error(tag));
        *success = 0;
        return 0.0f;
    }

    int rc = plc_tag_read(tag, DEFAULT_TIMEOUT);
    if(rc != PLCTAG_STATUS_OK) {
        fprintf(stderr, "Read failed for %s: %s\n", tag_path, plc_tag_decode_error(rc));
        plc_tag_destroy(tag);
        *success = 0;
        return 0.0f;
    }

    float value = plc_tag_get_float32(tag, 0);
    fprintf(stderr, "Read %.1f from %s\n", value, tag_path);

    plc_tag_destroy(tag);
    *success = 1;
    return value;
}

int main(int argc, char **argv)
{
    int timeout = DEFAULT_TIMEOUT;
    int num_indexes;
    int rc = PLCTAG_STATUS_OK;
    THREAD_HANDLE *threads;
    struct write_args *args;
    float *test_values;
    char *base_path;
    int i;
    int all_passed = 1;

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

    /* initialize synchronization primitives */
#if defined(WIN32) || defined(_WIN32)
    start_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    if(start_event == NULL) {
        fprintf(stderr, "ERROR: Failed to create start event!\n");
        return 1;
    }
#endif

    /* allocate memory */
    base_path = setup_tag_string(gateway, path, tag_name);
    test_values = (float *)calloc((size_t)num_indexes, sizeof(float));
    args = (struct write_args *)calloc((size_t)num_indexes, sizeof(struct write_args));
    threads = (THREAD_HANDLE *)calloc((size_t)num_indexes, sizeof(THREAD_HANDLE));

    if(!test_values || !args || !threads) {
        fprintf(stderr, "ERROR: Failed to allocate memory!\n");
        goto cleanup;
    }

    /* initialize test values */
    for(i = 0; i < num_indexes; i++) {
        test_values[i] = 11.0f + (float)i * 11.5f;
    }

    fprintf(stderr, "Starting write threads for tag %s (%d indexes)...\n", tag_name, num_indexes);

    /* launch threads */
    for(i = 0; i < num_indexes; i++) {
        args[i].base_path = base_path;
        args[i].index = i;
        args[i].value = test_values[i];
        args[i].success = 0;

#if defined(WIN32) || defined(_WIN32)
        threads[i] = CreateThread(NULL, 0, write_thread_func, &args[i], 0, NULL);
        if(threads[i] == NULL) {
            fprintf(stderr, "ERROR: Failed to create thread %d!\n", i);
            all_passed = 0;
            goto cleanup;
        }
#else
        if(pthread_create(&threads[i], NULL, write_thread_func, &args[i]) != 0) {
            fprintf(stderr, "ERROR: Failed to create thread %d!\n", i);
            all_passed = 0;
            goto cleanup;
        }
#endif
    }

    /* give threads time to start up */
    sleep_ms(100);

    fprintf(stderr, "Starting simultaneous write...\n");

    /* start all threads simultaneously */
#if defined(WIN32) || defined(_WIN32)
    SetEvent(start_event);
#else
    pthread_mutex_lock(&start_mutex);
    start_flag = 1;
    pthread_cond_broadcast(&start_cond);
    pthread_mutex_unlock(&start_mutex);
#endif

    /* wait for all threads to complete */
    for(i = 0; i < num_indexes; i++) {
#if defined(WIN32) || defined(_WIN32)
        WaitForSingleObject(threads[i], INFINITE);
        CloseHandle(threads[i]);
#else
        pthread_join(threads[i], NULL);
#endif
        if(!args[i].success) {
            fprintf(stderr, "Thread %d failed\n", i);
            all_passed = 0;
        }
    }

    if(!all_passed) {
        goto cleanup;
    }

    /* small delay to ensure writes complete */
    sleep_ms(100);

    /* read all values and validate */
    fprintf(stderr, "\nReading all values...\n");
    for(i = 0; i < num_indexes; i++) {
        int read_success = 0;
        float read_value = read_array_index(base_path, i, &read_success);

        if(!read_success) {
            all_passed = 0;
            continue;
        }

        if(read_value != test_values[i]) {
            fprintf(stderr, "ERROR: Mismatch at index %d: wrote %.1f, read %.1f\n",
                   i, test_values[i], read_value);
            all_passed = 0;
        } else {
            fprintf(stderr, "Values match for index %d\n", i);
        }
    }

cleanup:
    /* clean up */
#if defined(WIN32) || defined(_WIN32)
    if(start_event) CloseHandle(start_event);
#else
    pthread_mutex_destroy(&start_mutex);
    pthread_cond_destroy(&start_cond);
#endif

    free(base_path);
    free(test_values);
    free(args);
    free(threads);

    fprintf(stderr, "\nTest %s\n", all_passed ? "PASSED" : "FAILED");
    return all_passed ? 0 : 1;
}

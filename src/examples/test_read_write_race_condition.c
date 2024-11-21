/***************************************************************************
 *   Copyright (C) 2024 by Simon Labrecque                                 *
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
#include <stdint.h>
#include <stdbool.h>
#if defined(WIN32) || defined(_WIN32)
#include <Windows.h>
#else
#include <pthread.h>
#include <unistd.h>
#endif
#include "../lib/libplctag.h"
#include "utils.h"

#define REQUIRED_VERSION 2, 1, 0

#define READ_TAG_PATH "protocol=ab_eip&gateway=127.0.0.1&path=1,0&cpu=LGX&elem_size=4&elem_count=1&auto_sync_read_ms=50&name=Tag_To_Read"
#define WRITE_TAG_PATH "protocol=ab_eip&gateway=127.0.0.1&path=1,0&cpu=LGX&elem_size=4&elem_count=1&name=Tag_To_Write[1]"

#define DATA_TIMEOUT 5000
#define RUN_TIME_MS 5000
#define MAX_QUEUE_SIZE 20

void tag_callback(int32_t tag_id, int event, int status, void *userdata);

/* Write request structure */
struct write_request
{
    int32_t value;
    struct write_request *next;
};

/* Queue structure */
struct write_queue
{
    struct write_request *head;
    struct write_request *tail;
#if defined(WIN32) || defined(_WIN32)
    CRITICAL_SECTION mutex;
    HANDLE event;
#else
    pthread_mutex_t mutex;
    pthread_cond_t cond;
#endif
    int size;
    bool shutdown;
};

/* Test state structure */
struct tag_state
{
    int32_t read_tag;
    volatile int callback_count;
    volatile int write_count;
    volatile bool had_error;
    struct write_queue queue;
#if defined(WIN32) || defined(_WIN32)
    HANDLE worker_thread;
#else
    pthread_t worker_thread;
#endif
};

/* Initialize the write queue */
static void write_queue_init(struct write_queue *queue)
{
    queue->head = NULL;
    queue->tail = NULL;
    queue->size = 0;
    queue->shutdown = false;
#if defined(WIN32) || defined(_WIN32)
    InitializeCriticalSection(&queue->mutex);
    queue->event = CreateEvent(NULL, FALSE, FALSE, NULL);
#else
    pthread_mutex_init(&queue->mutex, NULL);
    pthread_cond_init(&queue->cond, NULL);
#endif
}

/* Add a write request to the queue */
static bool write_queue_push(struct write_queue *queue, int32_t value)
{
    struct write_request *req = calloc(1, sizeof(struct write_request));
    if (!req)
        return false;

    req->value = value;
    req->next = NULL;

#if defined(WIN32) || defined(_WIN32)
    EnterCriticalSection(&queue->mutex);
#else
    pthread_mutex_lock(&queue->mutex);
#endif

    if (queue->size >= MAX_QUEUE_SIZE)
    {
#if defined(WIN32) || defined(_WIN32)
        LeaveCriticalSection(&queue->mutex);
#else
        pthread_mutex_unlock(&queue->mutex);
#endif
        free(req);
        return false;
    }

    if (!queue->head)
    {
        queue->head = req;
    }
    else
    {
        queue->tail->next = req;
    }
    queue->tail = req;
    queue->size++;

#if defined(WIN32) || defined(_WIN32)
    SetEvent(queue->event);
    LeaveCriticalSection(&queue->mutex);
#else
    pthread_cond_signal(&queue->cond);
    pthread_mutex_unlock(&queue->mutex);
#endif
    return true;
}

/* Worker thread function */
#if defined(WIN32) || defined(_WIN32)
static DWORD WINAPI write_worker(LPVOID arg)
#else
static void *write_worker(void *arg)
#endif
{
    struct tag_state *state = (struct tag_state *)arg;
    struct write_queue *queue = &state->queue;

    while (1)
    {
#if defined(WIN32) || defined(_WIN32)
        EnterCriticalSection(&queue->mutex);
#else
        pthread_mutex_lock(&queue->mutex);
#endif

        while (!queue->head && !queue->shutdown)
        {
#if defined(WIN32) || defined(_WIN32)
            LeaveCriticalSection(&queue->mutex);
            WaitForSingleObject(queue->event, INFINITE);
            EnterCriticalSection(&queue->mutex);
#else
            pthread_cond_wait(&queue->cond, &queue->mutex);
#endif
        }

        if (queue->shutdown && !queue->head)
        {
#if defined(WIN32) || defined(_WIN32)
            LeaveCriticalSection(&queue->mutex);
#else
            pthread_mutex_unlock(&queue->mutex);
#endif
            break;
        }

        /* Get next write request */
        struct write_request *req = queue->head;
        queue->head = req->next;
        if (!queue->head)
        {
            queue->tail = NULL;
        }
        queue->size--;

#if defined(WIN32) || defined(_WIN32)
        LeaveCriticalSection(&queue->mutex);
#else
        pthread_mutex_unlock(&queue->mutex);
#endif

        int32_t write_tag = plc_tag_create(WRITE_TAG_PATH, DATA_TIMEOUT);
        if (write_tag < 0)
        {
            fprintf(stderr, "Failed to create write tag, error: %s\n",
                    plc_tag_decode_error(write_tag));
        }
        int rc = plc_tag_register_callback_ex(write_tag, tag_callback, &state);
        if (rc != PLCTAG_STATUS_OK)
        {
            fprintf(stderr, "Failed to register write callback, error: %s\n",
                    plc_tag_decode_error(rc));
        }

        /* Process write request */
        rc = plc_tag_set_int32(write_tag, 0, req->value);
        if (rc == PLCTAG_STATUS_OK)
        {
            rc = plc_tag_write(write_tag, DATA_TIMEOUT);
            if (rc != PLCTAG_STATUS_OK)
            {
                fprintf(stderr, "tag(%d) failed to write value %d, error: %s\n", write_tag, req->value, plc_tag_decode_error(rc));
                state->had_error = true;
            }
        }
        else
        {
            fprintf(stderr, "tag(%d) failed to set value %d, error: %s\n", write_tag, req->value, plc_tag_decode_error(rc));
            state->had_error = true;
        }

        free(req);
    }

#if defined(WIN32) || defined(_WIN32)
    return 0;
#else
    return NULL;
#endif
}

void tag_callback(int32_t tag_id, int event, int status, void *userdata)
{
    struct tag_state *state = (struct tag_state *)userdata;

    switch (event)
    {
    case PLCTAG_EVENT_WRITE_STARTED:
        // fprintf(stderr, "tag(%d) callback: PLCTAG_EVENT_WRITE_STARTED, %s\n", tag_id, plc_tag_decode_error(status));
        break;
    case PLCTAG_EVENT_READ_COMPLETED:
        if (status == PLCTAG_STATUS_OK)
        {
            if (tag_id == state->read_tag)
            {
                state->callback_count++;

                if (state->callback_count % 2 == 0)
                {
                    /* Queue write request */
                    if (!write_queue_push(&state->queue, 42))
                    {
                        fprintf(stderr, "Failed to queue write request\n");
                        state->had_error = true;
                        return;
                    }
                    ++state->write_count;
                }

                if (state->callback_count % 100 == 0)
                {
                    fprintf(stderr, "Processed %d reads and %d writes\n",
                            state->callback_count, state->write_count);
                }
            }
        }
        else
        {
            fprintf(stderr, "Read failed with status: %s\n", plc_tag_decode_error(status));
            state->had_error = true;
        }
        break;

    case PLCTAG_EVENT_WRITE_COMPLETED:

        if (status == PLCTAG_STATUS_OK)
        {
            state->write_count++;
        }
        else
        {
            fprintf(stderr, "tag(%d) Write failed with status: %s\n", tag_id, plc_tag_decode_error(status));
            state->had_error = true;
        }

        int rc = plc_tag_unregister_callback(tag_id);
        if (rc != PLCTAG_STATUS_OK)
        {
            fprintf(stderr, "Failed to unregister callback, error: %s\n", plc_tag_decode_error(rc));
            state->had_error = true;
        }

        // NB: if we add a small delay before plc_tag_destroy, we don't seem to trigger the bug, at least
        // for windows and macos; on linux, we still get `*** stack smashing detected ***: terminated`
        //util_sleep_ms(1);
        rc = plc_tag_destroy(tag_id);
        fprintf(stderr, "tag(%d) callback: PLCTAG_EVENT_WRITE_COMPLETED, destroyed tag, %s\n", tag_id, plc_tag_decode_error(status));
        if (rc != PLCTAG_STATUS_OK)
        {
            fprintf(stderr, "Failed to destroy tag, error: %s\n", plc_tag_decode_error(rc));
            state->had_error = true;
        }

        break;

    case PLCTAG_EVENT_ABORTED:
        fprintf(stderr, "tag(%d) Operation aborted!\n", tag_id);
        state->had_error = true;
        break;
    }
}

int main(int argc, char **argv)
{
    struct tag_state state = {0};
    int rc;

    /* check the library version */
    if (plc_tag_check_lib_version(REQUIRED_VERSION) != PLCTAG_STATUS_OK)
    {
        fprintf(stderr, "Required library version %d.%d.%d not available!\n", REQUIRED_VERSION);
        return 1;
    }

    /* initialize write queue */
    write_queue_init(&state.queue);

    /* create read tag */
    state.read_tag = plc_tag_create(READ_TAG_PATH, DATA_TIMEOUT);
    if (state.read_tag < 0)
    {
        fprintf(stderr, "Failed to create read tag, error: %s\n",
                plc_tag_decode_error(state.read_tag));
        return 1;
    }

    /* register callback */
    rc = plc_tag_register_callback_ex(state.read_tag, tag_callback, &state);
    if (rc != PLCTAG_STATUS_OK)
    {
        fprintf(stderr, "Failed to register read callback, error: %s\n",
                plc_tag_decode_error(rc));
        plc_tag_destroy(state.read_tag);
        return 1;
    }

    /* start worker thread */
#if defined(WIN32) || defined(_WIN32)
    state.worker_thread = CreateThread(NULL, 0, write_worker, &state, 0, NULL);
    if (!state.worker_thread)
    {
#else
    if (pthread_create(&state.worker_thread, NULL, write_worker, &state) != 0)
    {
#endif
        fprintf(stderr, "Failed to create worker thread\n");
        plc_tag_destroy(state.read_tag);
        return 1;
    }

    /* let it run */
    fprintf(stderr, "Test running for %d seconds...\n", RUN_TIME_MS / 1000);
    util_sleep_ms(RUN_TIME_MS);

    /* clean up */
    state.queue.shutdown = true;
#if defined(WIN32) || defined(_WIN32)
    SetEvent(state.queue.event);
    WaitForSingleObject(state.worker_thread, INFINITE);
    CloseHandle(state.worker_thread);
    DeleteCriticalSection(&state.queue.mutex);
    CloseHandle(state.queue.event);
#else
    pthread_cond_signal(&state.queue.cond);
    pthread_join(state.worker_thread, NULL);
    pthread_mutex_destroy(&state.queue.mutex);
    pthread_cond_destroy(&state.queue.cond);
#endif

    plc_tag_destroy(state.read_tag);

    /* report results */
    if (state.had_error)
    {
        fprintf(stderr, "Test failed with errors!\n");
        return 1;
    }

    fprintf(stderr, "Test completed successfully.\n");
    fprintf(stderr, "Processed %d reads and %d writes\n",
            state.callback_count, state.write_count);

    return 0;
}

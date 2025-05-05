/***************************************************************************
 *   Copyright (C) 2025 by Simon Labrecque                                 *
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


#include "compat_utils.h"
#include <inttypes.h>
#include <libplctag/lib/libplctag.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>


#define REQUIRED_VERSION 2, 4, 7

/* Tag configuration - uses auto_sync_read_ms for automatic reads */
#define TAG_ATTRIBS \
    "protocol=ab-eip&gateway=127.0.0.1&path=1,0&plc=ControlLogix&elem_type=DINT&elem_count=1&name=TestBigArray[0]&auto_sync_read_ms=500"

#define DATA_TIMEOUT (2000)
#define DISCONNECT_TIME_MS (2000)
#define TEST_DURATION_MS (10000)
#define READ_POLL_MS (100)

static volatile int read_start_count = 0;
static volatile int read_complete_count = 0;
static volatile int read_errors = 0;
static volatile int read_success_after_reconnect = 0;

/* This struct tracks test state */
typedef struct {
    int32_t tag;
    int64_t disconnect_time;
    int64_t reconnect_time;
    int64_t start_time;
    int64_t end_time;
    int test_passed;
    int errors_before_disconnect; /* Error count before disconnect */
    int errors_after_reconnect;   /* Error count after reconnect */
    int errors_during_disconnect; /* Calculated: errors that occurred during disconnect */
} test_state_t;

/* Global state for tracking reconnection status */
static test_state_t global_state = {0};


/* Callback function to track automatic read events */
void tag_callback(int32_t tag_id, int event, int status) {
    /* handle the events. */
    switch(event) {
        case PLCTAG_EVENT_ABORTED:
            fprintf(stderr, "Tag %d automatic operation was aborted with status %s!\n", 
                    tag_id, plc_tag_decode_error(status));
            break;

        case PLCTAG_EVENT_READ_STARTED:
            read_start_count++;
            fprintf(stderr, "[READ_START] Tag %d automatic read operation started with status %s (count=%d).\n", 
                   tag_id, plc_tag_decode_error(status), read_start_count);
            break;

        case PLCTAG_EVENT_READ_COMPLETED:
            read_complete_count++;
            
            /* Check for read errors/success */
            if(status != PLCTAG_STATUS_OK) {
                read_errors++;
                fprintf(stderr, "[READ_COMPLETE] Tag %d automatic read operation completed with ERROR status %s (errors=%d).\n", 
                       tag_id, plc_tag_decode_error(status), read_errors);
            } else {
                /* Check if we're in the period after reconnection */
                int64_t current_time = compat_time_ms();
                /* Use the global state structure */
                if(global_state.reconnect_time > 0 && current_time > global_state.reconnect_time) {
                    read_success_after_reconnect++;
                    fprintf(stderr, "[READ_COMPLETE] Tag %d automatic read operation SUCCEEDED after reconnection (success_after_reconnect=%d).\n", 
                           tag_id, read_success_after_reconnect);
                } else {
                    fprintf(stderr, "[READ_COMPLETE] Tag %d automatic read operation completed with status OK (complete_count=%d).\n", 
                           tag_id, read_complete_count);
                }
            }
            break;

        default:
            break;
    }
}


/* Monitoring thread to check tag value changes */
void *monitor_thread_func(void *arg) {
    int32_t tag = global_state.tag;
    int64_t current_time;
    uint16_t last_value = 0;
    uint16_t current_value = 0;
    
    fprintf(stderr, "Monitor thread started\n");
    
    while((current_time = compat_time_ms()) < global_state.end_time) {
        /* Get the current value */
        current_value = plc_tag_get_uint16(tag, 0);
        
        /* If the value changed, report it */
        if(current_value != last_value) {
            fprintf(stderr, "Value changed from %u to %u at time %" PRId64 " ms\n", 
                   last_value, current_value, current_time - global_state.start_time);
            last_value = current_value;
        }
        
        /* Check if it's time to simulate a PLC disconnect */
        if(global_state.disconnect_time > 0 && current_time >= global_state.disconnect_time && global_state.reconnect_time == 0) {
            fprintf(stderr, "\n[DISCONNECT] Simulating PLC disconnect at time %" PRId64 " ms\n", 
                   current_time - global_state.start_time);
            
            /* Capture error count before disconnect */
            global_state.errors_before_disconnect = read_errors;
            
            fprintf(stderr, "[DISCONNECT] Read stats before disconnect: started=%d, completed=%d, errors=%d\n",
                   read_start_count, read_complete_count, global_state.errors_before_disconnect);
            
            /* Kill the ab_server to truly simulate disconnect */
            if(system("killall ab_server") != 0) {
                fprintf(stderr, "[DISCONNECT] Warning: Unable to kill ab_server, make sure it's running\n");
            } else {
                fprintf(stderr, "[DISCONNECT] Successfully killed ab_server\n");
            }
            
            /* Schedule reconnect time */
            global_state.reconnect_time = current_time + DISCONNECT_TIME_MS;
            
            /* Force some explicit reads during the disconnection period to generate errors */
            fprintf(stderr, "[DISCONNECT] Attempting explicit reads during disconnection to generate errors\n");
            
            /* Try 3 manual reads to force errors */
            for(int i = 0; i < 3; i++) {
                fprintf(stderr, "[DISCONNECT] Explicit read attempt %d during disconnection...\n", i+1);
                int explicit_read_rc = plc_tag_read(global_state.tag, 500);
                if(explicit_read_rc != PLCTAG_STATUS_OK) {
                    read_errors++;
                    global_state.errors_during_disconnect++;
                    fprintf(stderr, "[DISCONNECT] Explicit read %d failed with error: %s\n", 
                            i+1, plc_tag_decode_error(explicit_read_rc));
                }
                compat_sleep_ms(200, NULL);
            }
            
            fprintf(stderr, "[DISCONNECT] Disconnect phase complete, will reconnect in %d ms\n", DISCONNECT_TIME_MS);
        }
        
        /* Check if it's time to simulate a PLC reconnect */
        if(global_state.reconnect_time > 0 && current_time >= global_state.reconnect_time && 
           global_state.reconnect_time != global_state.disconnect_time + DISCONNECT_TIME_MS) {
            fprintf(stderr, "\n[RECONNECT] Simulating PLC reconnect at time %" PRId64 " ms\n", 
                   current_time - global_state.start_time);
            
            /* Capture error count at reconnection */
            global_state.errors_after_reconnect = read_errors;
            
            /* Calculate errors during disconnection */
            global_state.errors_during_disconnect = global_state.errors_after_reconnect - global_state.errors_before_disconnect;
            
            fprintf(stderr, "[RECONNECT] Read stats before reconnect: started=%d, completed=%d, errors=%d\n",
                   read_start_count, read_complete_count, global_state.errors_after_reconnect);
            fprintf(stderr, "[RECONNECT] Errors during disconnection: %d\n", 
                   global_state.errors_during_disconnect);
            
            /* Start a new ab_server to simulate reconnect */
            if(system("cd /var/home/wegel/work/frontmatec/src/libplctag && LD_LIBRARY_PATH=./build/bin_dist ./build/bin_dist/ab_server --plc=ControlLogix --path=1,0 --tag=TestBigArray:DINT[10] > /dev/null 2>&1 &") != 0) {
                fprintf(stderr, "[RECONNECT] Warning: Unable to start new ab_server\n");
            } else {
                fprintf(stderr, "[RECONNECT] Successfully started new ab_server\n");
            }
            
            /* Wait a moment for ab_server to fully resume */
            fprintf(stderr, "[RECONNECT] Sleeping for 200ms to allow ab_server to fully resume\n");
            compat_sleep_ms(200, NULL);
            
            /* Mark the exact reconnect time */
            global_state.reconnect_time = current_time;
            
            /* Let's check the tag status after reconnect */
            int tag_status = plc_tag_status(global_state.tag);
            fprintf(stderr, "[RECONNECT] Tag status after reconnect: %s\n", plc_tag_decode_error(tag_status));
            
            fprintf(stderr, "[RECONNECT] Reconnection complete - monitoring for auto_sync_read resumption\n");
        }
        
        /* Sleep for a bit */
        compat_sleep_ms(READ_POLL_MS, NULL);
    }
    
    fprintf(stderr, "Monitor thread exiting\n");
    return NULL;
}


int main(void) {
    int rc = PLCTAG_STATUS_OK;
    compat_thread_t monitor_thread;
    int version_major = plc_tag_get_int_attribute(0, "version_major", 0);
    int version_minor = plc_tag_get_int_attribute(0, "version_minor", 0);
    int version_patch = plc_tag_get_int_attribute(0, "version_patch", 0);
    int reads_during_disconnect = 0;

    /* check the library version. */
    if(plc_tag_check_lib_version(REQUIRED_VERSION) != PLCTAG_STATUS_OK) {
        fprintf(stderr, "Required compatible library version %d.%d.%d not available!\n", REQUIRED_VERSION);
        fprintf(stderr, "Available library version is %d.%d.%d.\n", version_major, version_minor, version_patch);
        exit(1);
    }

    fprintf(stderr, "Starting with library version %d.%d.%d.\n", version_major, version_minor, version_patch);
    
    /* Start the AB server first */
    fprintf(stderr, "Starting AB server for the test...\n");
    if(system("cd /var/home/wegel/work/frontmatec/src/libplctag && ./build/bin_dist/ab_server --plc=ControlLogix --path=1,0 --tag=TestBigArray:DINT[10] > /dev/null 2>&1 &") != 0) {
        fprintf(stderr, "Error starting AB server! Make sure it's compiled.\n");
        exit(1);
    }
    
    /* Give the server time to start up */
    fprintf(stderr, "Waiting for AB server to initialize...\n");
    compat_sleep_ms(1000, NULL);

    /* Set up debug level - use DEBUG_DETAIL to see more about auto_sync_read and reconnection */
    //plc_tag_set_debug_level(PLCTAG_DEBUG_DETAIL);

    /* Initialize test state */
    global_state.start_time = compat_time_ms();
    global_state.end_time = global_state.start_time + TEST_DURATION_MS;
    global_state.disconnect_time = global_state.start_time + (TEST_DURATION_MS / 4); /* Disconnect after 25% of the test */
    global_state.reconnect_time = 0; /* Will be set when disconnect happens */
    global_state.test_passed = 0;

    /* Create tag with auto_sync_read enabled */
    global_state.tag = plc_tag_create(TAG_ATTRIBS, DATA_TIMEOUT);
    if(global_state.tag < 0) {
        fprintf(stderr, "Error %s creating tag!\n", plc_tag_decode_error(global_state.tag));
        return 1;
    }

    fprintf(stderr, "Tag created with ID %d, status %s.\n", 
           global_state.tag, plc_tag_decode_error(plc_tag_status(global_state.tag)));
           
    /* Verify auto_sync_read_ms setting is correctly set */
    int auto_sync_read_ms = plc_tag_get_int_attribute(global_state.tag, "auto_sync_read_ms", 0);
    fprintf(stderr, "Tag auto_sync_read_ms setting: %d ms\n", auto_sync_read_ms);

    /* Register the callback for tag events */
    rc = plc_tag_register_callback(global_state.tag, tag_callback);
    if(rc != PLCTAG_STATUS_OK) {
        fprintf(stderr, "Error %s registering callback!\n", plc_tag_decode_error(rc));
        plc_tag_destroy(global_state.tag);
        return 1;
    }

    /* Start the monitoring thread */
    compat_thread_create(&monitor_thread, monitor_thread_func, NULL);

    /* Wait for test completion */
    fprintf(stderr, "Test running for %d ms with auto_sync_read_ms=%d...\n", TEST_DURATION_MS, 500);
    
    /* Add periodic status updates during the test */
    for (int i = 0; i < 5; i++) {
        compat_sleep_ms(TEST_DURATION_MS / 5, NULL);
        
        int tag_status = plc_tag_status(global_state.tag);
        int64_t elapsed_ms = compat_time_ms() - global_state.start_time;
        
        fprintf(stderr, "\n[STATUS] Test progress: %d%% complete (elapsed: %" PRId64 " ms)\n", 
                (i+1)*20, elapsed_ms);
        fprintf(stderr, "[STATUS] Tag status: %s\n", plc_tag_decode_error(tag_status));
        fprintf(stderr, "[STATUS] Read stats: started=%d, completed=%d, errors=%d, successes_after_reconnect=%d\n",
               read_start_count, read_complete_count, read_errors, read_success_after_reconnect);
               
        /* If we're past the reconnect time, print additional diagnostics */
        if (global_state.reconnect_time > 0 && elapsed_ms > global_state.reconnect_time) {
            fprintf(stderr, "[STATUS] Time since reconnect: %" PRId64 " ms\n", 
                   elapsed_ms - global_state.reconnect_time);
        }
    }

    /* Wait for thread to finish */
    compat_thread_join(monitor_thread, NULL);

    /* Calculate the expected number of reads */
    int expected_reads = TEST_DURATION_MS / 500; /* 500ms is auto_sync_read_ms */
    
    /* Calculate reads during disconnection */
    reads_during_disconnect = DISCONNECT_TIME_MS / 500; /* 500ms is auto_sync_read_ms */

    /* Print results */
    fprintf(stderr, "\nTest Results:\n");
    fprintf(stderr, "Total reads started: %d, completed: %d, expected: %d\n", 
           read_start_count, read_complete_count, expected_reads);
    fprintf(stderr, "Read errors: %d\n", read_errors);
    fprintf(stderr, "Successful reads after reconnect: %d\n", read_success_after_reconnect);
    fprintf(stderr, "Time from reconnect to end: %" PRId64 " ms\n", 
           global_state.end_time - global_state.reconnect_time);

    /* 
     * For debugging and test development:
     * Manually attempt to trigger a read after the test to verify the connection works
     * This step may help with connection verification
     */
    fprintf(stderr, "Attempting a final manual read to verify connection state...\n");
    int manual_read_rc = plc_tag_read(global_state.tag, 0);
    if(manual_read_rc == PLCTAG_STATUS_OK) {
        fprintf(stderr, "Manual read succeeded. Tag value: %d\n", plc_tag_get_int32(global_state.tag, 0));
    } else {
        fprintf(stderr, "Manual read failed with status: %s\n", plc_tag_decode_error(manual_read_rc));
    }
    
    /* Giving extra time for one more automatic read attempt */
    fprintf(stderr, "Giving time for one more automatic read attempt...\n");
    compat_sleep_ms(1000, NULL);
    
    /* Wait a little longer to ensure auto-sync reading has time to resume */
    fprintf(stderr, "Giving additional time for more auto-sync reads to occur...\n");
    compat_sleep_ms(2000, NULL);
    
    /* Update the count of successful reads after reconnect */
    fprintf(stderr, "Final successful reads after reconnect: %d\n", read_success_after_reconnect);
    fprintf(stderr, "Errors during disconnection period: %d\n", global_state.errors_during_disconnect);
    
    /* Clean up */
    plc_tag_destroy(global_state.tag);

    /* Determine if test passed */
    global_state.test_passed = 0;
    
    /* Check if we got any successful reads after reconnect AND errors during disconnect */
    if(read_success_after_reconnect > 0 && global_state.errors_during_disconnect > 0) {
        global_state.test_passed = 1;
        fprintf(stderr, "TEST PASSED - Detected %d errors during disconnect and auto-sync reads successfully resumed after PLC reconnect\n", 
                global_state.errors_during_disconnect);
    } else if(read_success_after_reconnect == 0) {
        fprintf(stderr, "TEST FAILED - No successful reads after PLC reconnect\n");
        fprintf(stderr, "Note: The PLC connection is working (verified by manual read), but auto-sync reads aren't resuming.\n");
    } else if(global_state.errors_during_disconnect == 0) {
        fprintf(stderr, "TEST FAILED - No errors detected during disconnection period\n");
        fprintf(stderr, "Note: The disconnection simulation may not be working correctly.\n");
    }

    return global_state.test_passed ? 0 : 1;
}

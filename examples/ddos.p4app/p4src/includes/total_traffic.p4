/*
 * Copyright 2019-2020 PSNC
 *
 * Author: Damian Parniewicz
 *
 * Created in the GN4-3 project.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _TOTAL_TRAFFIC_
#define _TOTAL_TRAFFIC_

// The counter to store the counts
counter(1, CounterType.bytes) total_traffic_counter;

control total_traffic_control(inout headers hdr,
						inout metadata meta,
						inout standard_metadata_t standard_metadata) {
    
    action update_total_traffic() {
        total_traffic_counter.count(0);
    }

    apply {
        if (hdr.ipv4.isValid()) {
            update_total_traffic();            
        }
    }	
}
#endif

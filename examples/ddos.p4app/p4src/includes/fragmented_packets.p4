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

#ifndef _FRAGMENTED_PACKETS_
#define _FRAGMENTED_PACKETS_

// The counter to store the counts
counter(1, CounterType.bytes) fragmented_packets_counter;

control fragmented_packets_control(inout headers hdr,
				   inout metadata meta,
				   inout standard_metadata_t standard_metadata) {
    
    action update_fragmented_packets() {
        fragmented_packets_counter.count(0);
    }

    apply {
        if (hdr.ipv4.isValid()) {
	    bit<13> off;
	    bit<3> flag;
	    off = hdr.ipv4.fragOffset;
	    flag = hdr.ipv4.flags & 3w0b001;
	    if(off != 13w0 || flag == 3w0b001){
            	update_fragmented_packets();
	    }            
        }
    }	
}
#endif

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

#ifndef _SRC_DIST_MONITORING_
#define _SRC_DIST_MONITORING_

#include "src_dist_monitoring_bloom.p4"

const bit<32> SRC_DIST_CM_ROW = SKETCH_SIZE;  // number of cells in a single hash table row
const bit<32> SRC_DIST_THRESHOLD = 32w50;
const bit<32> SRC_DIST_HEAVY_HITTER_CNT = 10;  // how many heavy hitter src network address are reported to the controller

// The registers to store the counts
register<bit<32>> (SRC_DIST_CM_ROW) src_distribution_register1;
register<bit<32>> (SRC_DIST_CM_ROW) src_distribution_register2;
register<bit<32>> (SRC_DIST_CM_ROW) src_distribution_register3;
register<bit<32>> (SRC_DIST_CM_ROW) src_distribution_register4;

// TODO: replace with Digest
register<bit<32>> (SRC_DIST_HEAVY_HITTER_CNT) src_distribution_heavy_hitter; 
register<bit<32>> (SRC_DIST_HEAVY_HITTER_CNT) src_cnt_distribution_heavy_hitter; 
register<bit<32>> (1) src_distribution_heavy_hitter_index; 

control src_distribution_sketch_update(in register<bit<32>> hashtable,
                        in HashAlgorithm algo,
                        in headers hdr,
                        inout bit<32> count_value,
                        inout bit<32> hashtable_address) {
    
    action update_hashtable() { 
        hash(hashtable_address,
             algo,
             32w0,
             {hdr.ipv4.srcAddr & 32w0xFFFF0000>>16},
             SRC_DIST_CM_ROW);
        hashtable.read(count_value, hashtable_address);
        count_value = count_value + 32w1;
        hashtable.write(hashtable_address, count_value);
    }

    apply {
        if (hdr.ipv4.isValid()) {
            update_hashtable();
        }
    }
}

control src_distribution_sketch_control(inout headers hdr,
						inout metadata meta,
						inout standard_metadata_t standard_metadata) {

	src_distribution_sketch_update() update_hashtable_1;
	src_distribution_sketch_update() update_hashtable_2;
	src_distribution_sketch_update() update_hashtable_3;
	src_distribution_sketch_update() update_hashtable_4;
	
	src_distribution_bloom_control() bloom_filter;
	
	bit<32> count_val1 = 0;
	bit<32> count_val2 = 0;
	bit<32> count_val3 = 0;
	bit<32> count_val4 = 0;
	bit<32> count_min = 0;
	
	bit<32> hashtable_address1 = 0;
	bit<32> hashtable_address2 = 0;
	bit<32> hashtable_address3 = 0;
	bit<32> hashtable_address4 = 0;
	bit<32> hashtable_address = 0;
	bit<32> hashtable_id = 0;
	
	bit<1> already_sent = 0;
	bit<32> heavy_hitter_index = 0;
	
	apply {
		// update sketch cells basing on the packet
		update_hashtable_1.apply(src_distribution_register1, HashAlgorithm.crc32, hdr, count_val1, hashtable_address1);
		update_hashtable_2.apply(src_distribution_register2, HashAlgorithm.crc32_custom, hdr, count_val2, hashtable_address2);
		update_hashtable_3.apply(src_distribution_register3, HashAlgorithm.crc16, hdr, count_val3, hashtable_address3);
		update_hashtable_4.apply(src_distribution_register4, HashAlgorithm.crc16_custom, hdr, count_val4, hashtable_address4);
		
		// calculate a value of the count-min
		count_min = count_val1; hashtable_address = hashtable_address1; hashtable_id = 1;
		if (count_val2 < count_min) { count_min = count_val2; hashtable_address = hashtable_address2; hashtable_id = 2; }
		if (count_val3 < count_min) { count_min = count_val3; hashtable_address = hashtable_address3; hashtable_id = 3; }
		if (count_val4 < count_min) { count_min = count_val4; hashtable_address = hashtable_address4; hashtable_id = 4; }
		
		// check if heavy hitter
		if (count_min > SRC_DIST_THRESHOLD) {
			// this is a heavy hitter - notify the controller
			
			//check in bloom filter if src ip already sent and then update the bloom filter with the current packet
			bloom_filter.apply(hdr, meta, standard_metadata, already_sent);
			
			// getting index of a free register for passing output to the controller
			src_distribution_heavy_hitter_index.read(heavy_hitter_index, 0);
			
			if (already_sent == 1w0 && heavy_hitter_index < SRC_DIST_HEAVY_HITTER_CNT) {
			
				// sending a new src ip address to the controller 	
				src_distribution_heavy_hitter.write(heavy_hitter_index, hdr.ipv4.srcAddr & 32w0xFFFF0000);
				src_cnt_distribution_heavy_hitter.write(heavy_hitter_index, hashtable_address | (hashtable_id << 24));
				
				//activating a next free register with output for the controller
				src_distribution_heavy_hitter_index.write(0, heavy_hitter_index + 1);
			}
		} 
	}
	
}


#endif


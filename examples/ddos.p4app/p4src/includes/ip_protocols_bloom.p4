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

#ifndef _IP_PROTOCOLS_MONITORING_BLOOM_FILTER_
#define _IP_PROTOCOLS_MONITORING_BLOOM_FILTER_

const bit<32> IP_PROTOCOLS_BLOOM_ROW = 500;  // number of cells in a single hash table row

// The registers to store the bloom filter flags
register<bit<1>> (IP_PROTOCOLS_BLOOM_ROW) ip_protocols_distribution_bloom_register1;
register<bit<1>> (IP_PROTOCOLS_BLOOM_ROW) ip_protocols_distribution_bloom_register2;
register<bit<1>> (IP_PROTOCOLS_BLOOM_ROW) ip_protocols_distribution_bloom_register3;
register<bit<1>> (IP_PROTOCOLS_BLOOM_ROW) ip_protocols_distribution_bloom_register4;


control ip_protocols_distribution_bloom_update(
					in register<bit<1>> hashtable,
					in HashAlgorithm algo,
					in headers hdr,
					inout bit<1> last_value) {
    
    action update_hashtable() {
	
		bit<32> hashtable_address;
		hash(hashtable_address,
				 algo,
				 32w0,
				 {hdr.ipv4.protocol},
				 IP_PROTOCOLS_BLOOM_ROW);
		
		hashtable.read(last_value, hashtable_address);  // read last value of the filter (will be returned from the control)
		hashtable.write(hashtable_address,  1w1);  // set '1' as ip protocol seen
    }

    apply {
        if (hdr.ipv4.isValid()) {
            update_hashtable();
        }
    }
}



control ip_protocols_bloom_control(inout headers hdr,
						inout metadata meta,
						inout standard_metadata_t standard_metadata, 
						inout bit<1> already_in_filter) {

	ip_protocols_distribution_bloom_update() update_hashtable_1;
	ip_protocols_distribution_bloom_update() update_hashtable_2;
	ip_protocols_distribution_bloom_update() update_hashtable_3;
	ip_protocols_distribution_bloom_update() update_hashtable_4;
	
	bit<1> last_value_1 = 0;
	bit<1> last_value_2 = 0;
	bit<1> last_value_3 = 0;
	bit<1> last_value_4 = 0;
	
	apply {
			// get last filter values and update sketch cells basing on the packet 
			update_hashtable_1.apply(ip_protocols_distribution_bloom_register1, HashAlgorithm.crc32, hdr, last_value_1);
			update_hashtable_2.apply(ip_protocols_distribution_bloom_register2, HashAlgorithm.crc32_custom, hdr, last_value_2);
			update_hashtable_3.apply(ip_protocols_distribution_bloom_register3, HashAlgorithm.crc16, hdr, last_value_3);
			update_hashtable_4.apply(ip_protocols_distribution_bloom_register4, HashAlgorithm.crc16_custom, hdr, last_value_4);
			
			// check all registers if ip_protocols already present in the bloom filter (will be returned from the control)
			already_in_filter = last_value_1 | last_value_2 | last_value_3 | last_value_4;
	}	
}

#endif

#ifndef _PACKET_LENGTH_DISTRIBUTION_
#define _PACKET_LENGTH_DISTRIBUTION_

#include "packet_length_monitoring_bloom.p4"

const bit<32> PACKET_LENGTH_DIST_CM_ROW = 500;  // number of cells in a single hash table row
const bit<32> PACKET_LENGTH_THRESHOLD = 32w5;
const bit<32> PACKET_LENGTH_HITTER_CNT = 7;  // how many heavy hitter src port address are reported to the controller

// The registers to store the counts
register<bit<32>> (PACKET_LENGTH_DIST_CM_ROW) packet_length_distribution_register1;
register<bit<32>> (PACKET_LENGTH_DIST_CM_ROW) packet_length_distribution_register2;
register<bit<32>> (PACKET_LENGTH_DIST_CM_ROW) packet_length_distribution_register3;
register<bit<32>> (PACKET_LENGTH_DIST_CM_ROW) packet_length_distribution_register4;

// TODO: replace with Digest
register<bit<32>> (PACKET_LENGTH_HITTER_CNT) packet_length_distribution_heavy_hitter; 
register<bit<32>> (PACKET_LENGTH_HITTER_CNT) packet_length_cnt_distribution_heavy_hitter; 
register<bit<32>> (1) packet_length_distribution_heavy_hitter_index; 

control packet_length_distribution_sketch_update(in register<bit<32>> hashtable,
                        in HashAlgorithm algo,
                        in headers hdr,
			in standard_metadata_t standard_metadata,
                        inout bit<32> count_value,
                        inout bit<32> hashtable_address) {
    
    action update_hashtable() {
        hash(hashtable_address,
             algo,
             32w0,
             //{ hdr.ipv4.protocol},
	     {standard_metadata.packet_length},
             PACKET_LENGTH_DIST_CM_ROW);
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

control packet_length_control(inout headers hdr,
		     inout metadata meta,
		     inout standard_metadata_t standard_metadata) {

	packet_length_distribution_sketch_update() update_hashtable_1;
	packet_length_distribution_sketch_update() update_hashtable_2;
	packet_length_distribution_sketch_update() update_hashtable_3;
	packet_length_distribution_sketch_update() update_hashtable_4;

	packet_length_bloom_control() bloom_filter;
	
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
		/*update_hashtable_1.apply(packet_length_distribution_register1, HashAlgorithm.crc32, hdr, count_val1, hashtable_address1);
		update_hashtable_2.apply(packet_length_distribution_register2, HashAlgorithm.crc32_custom, hdr, count_val2, hashtable_address2);
		update_hashtable_3.apply(packet_length_distribution_register3, HashAlgorithm.crc16, hdr, count_val3, hashtable_address3);
		update_hashtable_4.apply(packet_length_distribution_register4, HashAlgorithm.crc16_custom, hdr, count_val4, hashtable_address4);*/
	
		
		update_hashtable_1.apply(packet_length_distribution_register1, HashAlgorithm.crc32, hdr, standard_metadata, count_val1, hashtable_address1);
		update_hashtable_2.apply(packet_length_distribution_register2, HashAlgorithm.crc32_custom, hdr, standard_metadata, count_val2, hashtable_address2);
		update_hashtable_3.apply(packet_length_distribution_register3, HashAlgorithm.crc16, hdr, standard_metadata, count_val3, hashtable_address3);
		update_hashtable_4.apply(packet_length_distribution_register4, HashAlgorithm.crc16_custom, hdr, standard_metadata, count_val4, hashtable_address4);

		// calculate a value of the count-min
		count_min = count_val1; hashtable_address = hashtable_address1; hashtable_id = 1;
		if (count_val2 < count_min) { count_min = count_val2; hashtable_address = hashtable_address2; hashtable_id = 2; }
		if (count_val3 < count_min) { count_min = count_val3; hashtable_address = hashtable_address3; hashtable_id = 3; }
		if (count_val4 < count_min) { count_min = count_val4; hashtable_address = hashtable_address4; hashtable_id = 4; }
		
		// check if heavy hitter
		if (count_min > PACKET_LENGTH_THRESHOLD) {
			// this is a heavy hitter - notify the controller
			
			//check in bloom filter if src port already sent and then update the bloom filter with the current packet
			bloom_filter.apply(hdr, meta, standard_metadata, already_sent);
			
			// getting index of a free register for passing output to the controller
			packet_length_distribution_heavy_hitter_index.read(heavy_hitter_index, 0);
			
			if (already_sent == 1w0 && heavy_hitter_index < PACKET_LENGTH_HITTER_CNT) {
			
				// sending a new ip protocols dist to the controller 		
				//packet_length_distribution_heavy_hitter.write(heavy_hitter_index, (bit<32>)hdr.ipv4.protocol); 		
				packet_length_distribution_heavy_hitter.write(heavy_hitter_index, (bit<32>)standard_metadata.packet_length);

				packet_length_cnt_distribution_heavy_hitter.write(heavy_hitter_index, hashtable_address | (hashtable_id << 24));
				
				//activating a next free register with output for the controller
				packet_length_distribution_heavy_hitter_index.write(0, heavy_hitter_index + 1);
			}
		} 
	}	
}
#endif

#ifndef _SRC_PORT_DIST_MONITORING_
#define _SRC_PORT_DIST_MONITORING_

#include "src_port_dist_monitoring_bloom.p4"

const bit<32> SRC_PORT_DIST_CM_ROW = SKETCH_SIZE;  // number of cells in a single hash table row
const bit<32> SRC_PORT_DIST_THRESHOLD = 32w50;
const bit<32> SRC_PORT_HEAVY_HITTER_CNT = 10;  // how many heavy hitter src port address are reported to the controller

// The registers to store the counts
register<bit<32>> (SRC_PORT_DIST_CM_ROW) src_port_distribution_register1;
register<bit<32>> (SRC_PORT_DIST_CM_ROW) src_port_distribution_register2;
register<bit<32>> (SRC_PORT_DIST_CM_ROW) src_port_distribution_register3;
register<bit<32>> (SRC_PORT_DIST_CM_ROW) src_port_distribution_register4;

// TODO: replace with Digest
register<bit<32>> (SRC_PORT_HEAVY_HITTER_CNT) src_port_distribution_heavy_hitter; 
register<bit<32>> (SRC_PORT_HEAVY_HITTER_CNT) src_port_cnt_distribution_heavy_hitter; 
register<bit<32>> (1) src_port_distribution_heavy_hitter_index; 

control src_port_distribution_sketch_update(in register<bit<32>> hashtable,
                        in HashAlgorithm algo,
                        in headers hdr,
                        inout bit<32> count_value,
                        inout bit<32> hashtable_address) {
    
    action udp_update_hashtable() {
        hash(hashtable_address,
             algo,
             32w0,
             { hdr.udp.srcPort},
             SRC_PORT_DIST_CM_ROW);
        hashtable.read(count_value, hashtable_address);
        count_value = count_value + 32w1;
        hashtable.write(hashtable_address, count_value);
    }
    action tcp_update_hashtable() {
        hash(hashtable_address,
             algo,
             32w0,
             { hdr.tcp.srcPort},
             SRC_PORT_DIST_CM_ROW);
        hashtable.read(count_value, hashtable_address);
        count_value = count_value + 32w1;
        hashtable.write(hashtable_address, count_value);
    }

    apply {
        if (hdr.udp.isValid()) {
            udp_update_hashtable();
        }
        if (hdr.tcp.isValid()) {
            tcp_update_hashtable();
        }
    }
}

control src_port_distribution_sketch_control(inout headers hdr,
						inout metadata meta,
						inout standard_metadata_t standard_metadata) {

	src_port_distribution_sketch_update() update_hashtable_1;
	src_port_distribution_sketch_update() update_hashtable_2;
	src_port_distribution_sketch_update() update_hashtable_3;
	src_port_distribution_sketch_update() update_hashtable_4;
	
	src_port_distribution_bloom_control() bloom_filter;
	
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
		update_hashtable_1.apply(src_port_distribution_register1, HashAlgorithm.crc32, hdr, count_val1, hashtable_address1);
		update_hashtable_2.apply(src_port_distribution_register2, HashAlgorithm.crc32_custom, hdr, count_val2, hashtable_address2);
		update_hashtable_3.apply(src_port_distribution_register3, HashAlgorithm.crc16, hdr, count_val3, hashtable_address3);
		update_hashtable_4.apply(src_port_distribution_register4, HashAlgorithm.crc16_custom, hdr, count_val4, hashtable_address4);
		
		// calculate a value of the count-min
		count_min = count_val1; hashtable_address = hashtable_address1; hashtable_id = 1;
		if (count_val2 < count_min) { count_min = count_val2; hashtable_address = hashtable_address2; hashtable_id = 2; }
		if (count_val3 < count_min) { count_min = count_val3; hashtable_address = hashtable_address3; hashtable_id = 3; }
		if (count_val4 < count_min) { count_min = count_val4; hashtable_address = hashtable_address4; hashtable_id = 4; }
		
		// check if heavy hitter
		if (count_min > SRC_PORT_DIST_THRESHOLD) {
			
			// this is a heavy hitter - notify the controller
			bloom_filter.apply(hdr, meta, standard_metadata, already_sent);

			src_port_distribution_heavy_hitter_index.read(heavy_hitter_index, 0);
			if (already_sent == 1w0 && heavy_hitter_index < SRC_PORT_HEAVY_HITTER_CNT) {
				// network src port haven't been sent to the controller earlier
				
				src_port_distribution_heavy_hitter.write(heavy_hitter_index,(bit<32>) hdr.udp.srcPort);
				src_port_cnt_distribution_heavy_hitter.write(heavy_hitter_index, hashtable_address | (hashtable_id << 24));
				
				src_port_distribution_heavy_hitter_index.write(0, heavy_hitter_index + 1);
			}
		} 
	}	
}
#endif


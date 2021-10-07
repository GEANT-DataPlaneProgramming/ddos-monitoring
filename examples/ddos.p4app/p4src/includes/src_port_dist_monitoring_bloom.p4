#ifndef _SRC_PORT_DIST_MONITORING_BLOOM_FILTER_
#define _SRC_PORT_DIST_MONITORING_BLOOM_FILTER_

const bit<32> SRC_PORT_DIST_BLOOM_ROW = SKETCH_SIZE;  // number of cells in a single hash table row

// The registers to store the bloom filter flags
register<bit<1>> (SRC_PORT_DIST_BLOOM_ROW) src_port_distribution_bloom_register1;
register<bit<1>> (SRC_PORT_DIST_BLOOM_ROW) src_port_distribution_bloom_register2;
register<bit<1>> (SRC_PORT_DIST_BLOOM_ROW) src_port_distribution_bloom_register3;
register<bit<1>> (SRC_PORT_DIST_BLOOM_ROW) src_port_distribution_bloom_register4;


control src_port_distribution_bloom_update(
					in register<bit<1>> hashtable,
					in HashAlgorithm algo,
					in headers hdr,
					inout bit<1> last_value) {
    
    action update_hashtable() {
	
		bit<32> hashtable_address;
		hash(hashtable_address,
				 algo,
				 32w0,
				 {hdr.udp.srcPort},
				 SRC_PORT_DIST_BLOOM_ROW);
		
		hashtable.read(last_value, hashtable_address);  // read last value of the filter (will be returned from the control)
		hashtable.write(hashtable_address,  1w1);  // set '1' as network address seen
    }

    apply {
        if (hdr.ipv4.isValid()) {
            update_hashtable();
        }
    }
}



control src_port_distribution_bloom_control(inout headers hdr,
						inout metadata meta,
						inout standard_metadata_t standard_metadata, 
						inout bit<1> already_in_filter) {

	src_port_distribution_bloom_update() update_hashtable_1;
	src_port_distribution_bloom_update() update_hashtable_2;
	src_port_distribution_bloom_update() update_hashtable_3;
	src_port_distribution_bloom_update() update_hashtable_4;
	
	bit<1> last_value_1 = 0;
	bit<1> last_value_2 = 0;
	bit<1> last_value_3 = 0;
	bit<1> last_value_4 = 0;
	
	apply {
			// get last filter values and update sketch cells basing on the packet 
			update_hashtable_1.apply(src_port_distribution_bloom_register1, HashAlgorithm.crc32, hdr, last_value_1);
			update_hashtable_2.apply(src_port_distribution_bloom_register2, HashAlgorithm.crc32_custom, hdr, last_value_2);
			update_hashtable_3.apply(src_port_distribution_bloom_register3, HashAlgorithm.crc16, hdr, last_value_3);
			update_hashtable_4.apply(src_port_distribution_bloom_register4, HashAlgorithm.crc16_custom, hdr, last_value_4);
			
			// check all registers if src port address already present in the bloom filter (will be returned from the control)
			already_in_filter = last_value_1 | last_value_2 | last_value_3 | last_value_4;
	}	
}

#endif


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

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

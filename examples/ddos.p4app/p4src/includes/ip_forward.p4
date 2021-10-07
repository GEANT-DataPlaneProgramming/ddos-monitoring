#include <core.p4>
#include <v1model.p4>

#ifndef _IP_FORWARD_P4_
#define _IP_FORWARD_P4_

@name("_drop") 
action _drop() {
	mark_to_drop();
}

control ip_forward_ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
	
	@name("set_forward")
	action set_forward(bit<48> dmac, bit<9> port) {
		hdr.ethernet.dstAddr = dmac;
		standard_metadata.egress_port = port;
		hdr.ipv4.ttl = hdr.ipv4.ttl + 8w255;
	}
	
	@name("forward") 
	table forward {
		key = {
			hdr.ipv4.dstAddr: lpm;
		}
		actions = {
			_drop;
			set_forward;
			NoAction;
		}
		size = 1024;
		default_action = NoAction();
	}

    apply {
        if (hdr.ipv4.isValid()) {
          forward.apply();
        }
    }
}

control ip_forward_egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

	@name("rewrite_smac") 
	action rewrite_smac(bit<48> smac) {
		hdr.ethernet.srcAddr = smac;
	}

	@name("send_frame") 
	table send_frame {
		key = {
			meta.egress_port: exact;
		}
		actions = {
			rewrite_smac;
			_drop;
			NoAction;
		}
		size = 256;
		default_action = NoAction();
	}

    apply {
        if (hdr.ipv4.isValid()) {
          send_frame.apply();
        }
    }
}


#endif
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

/////////////////////////////////////////////////////////////////////////////////////////////////////////
const bit<32> SKETCH_SIZE = 50;


#include "includes/headers.p4"
#include "includes/parser.p4"
#include "includes/ip_forward.p4"
#include "includes/src_dist_monitoring.p4"
#include "includes/src_port_dist_monitoring.p4"
#include "includes/dst_port_dist_monitoring.p4"
#include "includes/total_traffic.p4"
#include "includes/fragmented_packets.p4"
#include "includes/ip_protocols.p4"
#include "includes/packet_length_monitoring.p4"


control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    ip_forward_ingress() ip_forward;
    src_distribution_sketch_control() src_distribution_sketch;
    src_port_distribution_sketch_control() src_port_distribution_sketch;
    dst_port_distribution_sketch_control() dst_port_distribution_sketch;
    total_traffic_control() total_traffic;
    fragmented_packets_control() fragmented_packets;
    ip_protocols_control() ip_protocols;
    packet_length_control() packet_length_dist;  
   
    
    action src_distribution_monitor() {
        // INFO: bvm2 target don't accept this valid P4_16 statement
        // 'action_run' used instead in the control
        // src_distribution_sketch.apply(hdr, meta, standard_metadata);  
    }

    action src_port_distribution_monitor() {
        // INFO: bvm2 target don't accept this valid P4_16 statement
        // 'action_run' used instead in the control
        // src_port_distribution_sketch.apply(hdr, meta, standard_metadata);  
    }	

    action dst_port_distribution_monitor() {
        // INFO: bvm2 target don't accept this valid P4_16 statement
        // 'action_run' used instead in the control
        // dst_port_distribution_sketch.apply(hdr, meta, standard_metadata);  
    }
    
    action total_traffic_distribution_monitor() {
        // INFO: bvm2 target don't accept this valid P4_16 statement
        // 'action_run' used instead in the control
        // total_traffic.apply(hdr, meta, standard_metadata);  
    }

    action fragmented_packets_distribution_monitor() {
        // INFO: bvm2 target don't accept this valid P4_16 statement
        // 'action_run' used instead in the control
        // total_traffic.apply(hdr, meta, standard_metadata);  
    }

    action ip_protocols_distribution_monitor() {
        // INFO: bvm2 target don't accept this valid P4_16 statement
        // 'action_run' used instead in the control
        // ip_protocols.apply(hdr, meta, standard_metadata);  
    }

    action packet_length_distribution_monitor() {
        // INFO: bvm2 target don't accept this valid P4_16 statement
        // 'action_run' used instead in the control
        // packet_length.apply(hdr, meta, standard_metadata);  
    }

    action all_distribution_monitor() {
        // INFO: bvm2 target don't accept this valid P4_16 statement
        // 'action_run' used instead in the control
        // ip_protocols.apply(hdr, meta, standard_metadata);
    }

    /* Table used for DDoS algorithms activation
    * The controller adds table entry with detected DDoS destination address and action pointing to proper algorithm 
    */
    @name("ddos_destinations_monitored") 
    table ddos_destinations_monitored {
            key = {
                    hdr.ipv4.dstAddr : lpm;
            }
            actions = {
                    src_distribution_monitor;					
                    src_port_distribution_monitor;
                    dst_port_distribution_monitor;					
                    total_traffic_distribution_monitor;
		    fragmented_packets_distribution_monitor;
                    ip_protocols_distribution_monitor;
		    packet_length_distribution_monitor;
                    all_distribution_monitor;
                    NoAction;
            }
            default_action = NoAction();
    }
    
    apply {
        ip_forward.apply(hdr, meta, standard_metadata);
        switch(ddos_destinations_monitored.apply().action_run) {
            src_distribution_monitor: { src_distribution_sketch.apply(hdr, meta, standard_metadata); return;}
            src_port_distribution_monitor: { src_port_distribution_sketch.apply(hdr, meta, standard_metadata); return;}
            dst_port_distribution_monitor: { dst_port_distribution_sketch.apply(hdr, meta, standard_metadata); return;}		
            total_traffic_distribution_monitor:{ total_traffic.apply(hdr, meta, standard_metadata); return;}	
	    fragmented_packets_distribution_monitor:{ fragmented_packets.apply(hdr, meta, standard_metadata); return;}		
            ip_protocols_distribution_monitor: { ip_protocols.apply(hdr, meta, standard_metadata); return;}
	    packet_length_distribution_monitor: { packet_length_dist.apply(hdr, meta, standard_metadata); return;}
            all_distribution_monitor: {
                src_distribution_sketch.apply(hdr, meta, standard_metadata);
                src_port_distribution_sketch.apply(hdr, meta, standard_metadata);
                dst_port_distribution_sketch.apply(hdr, meta, standard_metadata);
                total_traffic.apply(hdr, meta, standard_metadata);
		fragmented_packets.apply(hdr, meta, standard_metadata);
                ip_protocols.apply(hdr, meta, standard_metadata);
		packet_length_dist.apply(hdr, meta, standard_metadata);
                return;
            }
        }
    }	
}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), ip_forward_egress(), computeChecksum(), DeparserImpl()) main;


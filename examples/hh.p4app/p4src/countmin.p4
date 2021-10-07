/* Copyright 2013-present Barefoot Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "includes/headers.p4"
#include "includes/parser.p4"

// TODO: Define the threshold value
#define CM_ROW 30
#define THRESHOLD 10
field_list ipv4_checksum_list {
        ipv4.version;
        ipv4.ihl;
        ipv4.diffserv;
        ipv4.totalLen;
        ipv4.identification;
        ipv4.flags;
        ipv4.fragOffset;
        ipv4.ttl;
        ipv4.protocol;
        ipv4.srcAddr;
        ipv4.dstAddr;
}

field_list_calculation ipv4_checksum {
    input {
        ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field ipv4.hdrChecksum  {
    verify ipv4_checksum;
    update ipv4_checksum;
}

action _drop() {
    drop();
}

//
//==========addtional headers========
// hash values and counts
header_type custom_metadata_t {
    fields {
        nhop_ipv4: 32;
        // TODO: Add the metadata for hash indices and count values
        hash_val1: 16;
        hash_val2: 16;
        hash_val3: 16;
        hash_val4: 16;
        count_val1: 32;
        count_val2: 32;
        count_val3: 32;
        count_val4: 32;
        count_min: 32;
    }
}

metadata custom_metadata_t custom_metadata;
// store src, dst and counts
header_type heavy_hitter_t{
        fields {
            srcAddr: 32;
            dstAddr: 32;
            count: 32;
            }
}
metadata heavy_hitter_t heavy_hitter;

//


//===============additional parsers ============

/*parser parse_hh_report*/
/*{*/
    /*extract(hh_report);*/
    /*return ingress;*/
    /*}*/
//
//==================================================



// TODO: Define the field list to compute the hash on
// Use the 5 tuple of 
// (src ip, dst ip, src port, dst port, ip protocol)

field_list hash_fields {
    ipv4.srcAddr;
    ipv4.dstAddr;
}

// TODO: Define four different hash functions to store the counts
// Please use xxhash64 for the hash functions
field_list_calculation heavy_hitter_hash1 {
    input { 
        hash_fields;
    }
    algorithm : xxhash64_1;
    output_width : 16;
}

field_list_calculation heavy_hitter_hash2 {
    input { 
        hash_fields;
    }
    algorithm : xxhash64_2;
    output_width : 16;
}

field_list_calculation heavy_hitter_hash3 {
    input { 
        hash_fields;
    }
    algorithm : xxhash64_3;
    output_width : 16;
}

field_list_calculation heavy_hitter_hash4 {
    input { 
        hash_fields;
    }
    algorithm : xxhash64_4;
    output_width : 16;
}



// TODO: Define the registers to store the counts
register heavy_hitter_register1{
    width : 32;
    instance_count : CM_ROW;
}

register heavy_hitter_register2{
    width : 32;
    instance_count : CM_ROW;
}

register heavy_hitter_register3{
    width : 32;
    instance_count : CM_ROW;
}

register heavy_hitter_register4{
    width : 32;
    instance_count : CM_ROW;
}

register hh_r{
    width : 32;
    instance_count : 3;  //0: srcAddr, 1: dstAddr, 2: count
}




@pragma netro reglocked heavy_hitter_register1;
@pragma netro reglocked heavy_hitter_register2;
@pragma netro reglocked heavy_hitter_register3;
@pragma netro reglocked heavy_hitter_register4;
@pragma netro reglocked hh_r;
@pragma netro reglocked packet_tot;
@pragma netro reglocked sampleList_src;
@pragma netro reglocked sampleList_dst;
@pragma netro reglocked sampleList_count;
@pragma netro reglocked sampleList_index;
@pragma netro reglocked maximum_count;



// TODO: Actions to set heavy hitter filter
action set_heavy_hitter_count() {
//get the hash value
    modify_field_with_hash_based_offset(custom_metadata.hash_val1, 0,
                                        heavy_hitter_hash1, CM_ROW);
    modify_field_with_hash_based_offset(custom_metadata.hash_val2, 0,
                                        heavy_hitter_hash2, CM_ROW);
    modify_field_with_hash_based_offset(custom_metadata.hash_val3, 0,
                                        heavy_hitter_hash3, CM_ROW);
    modify_field_with_hash_based_offset(custom_metadata.hash_val4, 0,
                                        heavy_hitter_hash4, CM_ROW);

//read the counter value from the register counter table
    register_read(custom_metadata.count_val1, heavy_hitter_register1, custom_metadata.hash_val1);
    register_read(custom_metadata.count_val2, heavy_hitter_register2, custom_metadata.hash_val2);
    register_read(custom_metadata.count_val3, heavy_hitter_register3, custom_metadata.hash_val3);
    register_read(custom_metadata.count_val4, heavy_hitter_register4, custom_metadata.hash_val4);
//update the counter value
    add_to_field(custom_metadata.count_val1, 0x01);
    add_to_field(custom_metadata.count_val2, 0x01);
    add_to_field(custom_metadata.count_val3, 0x01);
    add_to_field(custom_metadata.count_val4, 0x01);
//write back the register
    register_write(heavy_hitter_register1, custom_metadata.hash_val1, custom_metadata.count_val1);
    register_write(heavy_hitter_register2, custom_metadata.hash_val2, custom_metadata.count_val2);
    register_write(heavy_hitter_register3, custom_metadata.hash_val3, custom_metadata.count_val3);
    register_write(heavy_hitter_register4, custom_metadata.hash_val4, custom_metadata.count_val4);
    
}
@pragma netro no_lookup_caching set_heavy_hitter_count;



// Find the minimum value in CMS
action do_find_min1()
{
    modify_field(custom_metadata.count_min, custom_metadata.count_val1);
}

action do_find_min2()
{
    modify_field(custom_metadata.count_min, custom_metadata.count_val2);
}

action do_find_min3()
{
    modify_field(custom_metadata.count_min, custom_metadata.count_val3);
}

action do_find_min4()
{
    modify_field(custom_metadata.count_min, custom_metadata.count_val4);
}

action do_read_hh()
{
    register_read(heavy_hitter.srcAddr, hh_r, 0);
    register_read(heavy_hitter.dstAddr, hh_r, 1);
    register_read(heavy_hitter.count, hh_r, 2);
}


action do_update_hh()
{
    register_write(hh_r, 0, ipv4.srcAddr);
    register_write(hh_r, 1, ipv4.dstAddr);
    register_write(hh_r, 2, custom_metadata.count_min);
}
action ipv4_forward(dstAddr, port) {
                modify_field(standard_metadata.egress_spec, port);
                modify_field(ethernet.srcAddr, ethernet.dstAddr);
                modify_field(ethernet.dstAddr, dstAddr);
                subtract_from_field(ipv4.ttl, 1);
                }



// TODO: Define the tables to run actions
table set_heavy_hitter_count_table {
    actions {
        set_heavy_hitter_count;
    }
    size: 1;
}

//

//
table find_min1
{
    actions
    {
        do_find_min1;
        }
}
//
table find_min2
{
    actions
    {
        do_find_min2;
    }
}
//
table find_min3
{
    actions
    {
        do_find_min3;
    }
}
//
table find_min4
{
    actions
    {
        do_find_min4;
    }
}

//


table read_hh
{
    actions
    {
        do_read_hh;
    }
}
//
table update_hh
{
    actions
    {
        do_update_hh;
    }
}
//
table ipv4_lpm{
    reads{
        ipv4.dstAddr : lpm;
        }
    actions{
        ipv4_forward;
        _drop;
        }
    size: 1024;
    }
//
//==========================================================================================================
//Time collection
//==========================================================================================================
action rewrite_mac(smac) {
    modify_field(ethernet.srcAddr, smac);
}

table send_frame {
    reads {
        standard_metadata.egress_port: exact;
    }
    actions {
        rewrite_mac;
        _drop;
    }
    size: 256;
}


control ingress {
    // TODO: Add table control here
    apply(ipv4_lpm);
    apply(set_heavy_hitter_count_table);
    apply(find_min1);
    if(custom_metadata.count_min > custom_metadata.count_val2){
        apply(find_min2);
    }
    if(custom_metadata.count_min > custom_metadata.count_val3){
        apply(find_min3);
    }
    if(custom_metadata.count_min > custom_metadata.count_val4){
        apply(find_min4);
    }

    if (custom_metadata.count_min > THRESHOLD){ 
            apply(read_hh);
        if (heavy_hitter.count < custom_metadata.count_min){
            apply(update_hh);
        }
    }
}
control egress {
    apply(send_frame);
}

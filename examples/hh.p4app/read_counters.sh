#!/bin/bash

# Copyright 2013-present Barefoot Networks, Inc. 
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

THIS_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source $THIS_DIR/../../env.sh

CLI_PATH=$BMV2_PATH/targets/simple_switch/sswitch_CLI

echo "displaying counters for h1"
echo "register_read packet_tot 0" | $CLI_PATH heavy_hitter.json 22222
echo
echo "displaying counters for h2"
echo "register_read packet_tot 0" | $CLI_PATH heavy_hitter.json 22223
echo
echo "displaying counters for h3"
echo "register_read packet_tot 0" | $CLI_PATH heavy_hitter.json 22224
echo
#echo "resetting counters"
#echo "counter_reset ip_src_counter" | $CLI_PATH heavy_hitter.json 22222
echo



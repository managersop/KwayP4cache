
#include <core.p4>
#include <v1model.p4>

#define MAX_ENTRIES 2
#define MAIN_CACHE_SIZE 2
#define FRONT_CACHE_SIZE 2
#define ELEMENT_SIZE 48
#define KEY_SIZE 16
#define COUNTER_SIZE 32

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

const bit<16> P4KWAY_ETYPE = 0x1234;
const bit<8>  P4KWAY_P     = 0x50;   // 'P'
const bit<8>  P4KWAY_4     = 0x34;   // '4'
const bit<8>  P4KWAY_VER   = 0x01;   // v0.1
const bit<8>  P4GET_VAL_LFU  = 0x46;   // 'F'
const bit<8>  P4GET_VAL_FIFO  = 0x52;   // 'R'

header p4kway_t {
   bit<8>  p;
   bit<8>  four;
   bit<8>  ver;
   bit<8>  front_type;
   bit<8>  main_type;
   bit<16> k;
   bit<16> v;
   bit<8> cache;
   bit<8> front;
}

struct headers {
    ethernet_t   ethernet;
    p4kway_t     p4kway;
}

struct metadata {
    /* In our case it is empty */
}

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {    
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            P4KWAY_ETYPE : check_p4kway;
            default      : accept;
        }
    }
    
    state check_p4kway{
        transition select(packet.lookahead<p4kway_t>().p,
        packet.lookahead<p4kway_t>().four,
        packet.lookahead<p4kway_t>().ver) {
            (P4KWAY_P, P4KWAY_4, P4KWAY_VER) : parse_p4kway;
            default                          : accept;
        }
    }
    
    state parse_p4kway {
        packet.extract(hdr.p4kway);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr,
                         inout metadata meta) {
    apply { }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    register<bit<(COUNTER_SIZE)>>(65535) r_counter;
    register<bit<32>>(1) r_timestamp;

    // Elements cache
    register<bit<(ELEMENT_SIZE * MAIN_CACHE_SIZE)>>(MAX_ENTRIES) r_main_cache;  // MAX_ENTRIES Elements. Each element is 32 bit.
    register<bit<(ELEMENT_SIZE * FRONT_CACHE_SIZE)>>(MAX_ENTRIES) r_front_cache;

    // Victim element. Common for the two caches.
    register<bit<ELEMENT_SIZE>>(MAX_ENTRIES) r_victim_element;

    // Keys cache
    register<bit<(KEY_SIZE * MAIN_CACHE_SIZE)>>(MAX_ENTRIES) r_main_keys;
    register<bit<(KEY_SIZE * FRONT_CACHE_SIZE)>>(MAX_ENTRIES) r_front_keys;
    
    // Victim Key. Common for thw two cached
    register<bit<KEY_SIZE>>(MAX_ENTRIES) r_victim_key; 
    
    // Masks to check whether or not the requested key is in the cache
    bit<(KEY_SIZE * MAIN_CACHE_SIZE)> main_keys_mask;
    bit<(KEY_SIZE * FRONT_CACHE_SIZE)> front_keys_mask;
    
    // Bit that represent the keys in the cache
    bit<(KEY_SIZE * FRONT_CACHE_SIZE)> front_keys_bit;
    bit<(KEY_SIZE * MAIN_CACHE_SIZE)> main_keys_bit;

    
    action send_back() {
       bit<48> tmp;

        /* Swap the MAC addresses */
        tmp = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = tmp;

        /* Send the packet back to the port it came from */
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    action insert_key_to_front_keys_register(in bit<32> h, in bit<32> index, in bit<KEY_SIZE> key_to_insert, out bit<KEY_SIZE> new_victim_key) {
        bit<(KEY_SIZE * FRONT_CACHE_SIZE)> keys;
        r_front_keys.read(keys, h);
        
if (index == 0) {
    new_victim_key = keys[15:0];
    keys[15:0] = key_to_insert;
} 

if (index == 1) {
    new_victim_key = keys[31:16];
    keys[31:16] = key_to_insert;
} 
        r_front_keys.write(h, keys);
    }

    action insert_key_to_main_keys_register(in bit<32> h, in bit<32> index, in bit<KEY_SIZE> key_to_insert, out bit<KEY_SIZE> new_victim_key) {
        bit<(KEY_SIZE * MAIN_CACHE_SIZE)> keys;
        r_main_keys.read(keys, h);
        
if (index == 0) {
    new_victim_key = keys[15:0];
    keys[15:0] = key_to_insert;
} 

if (index == 1) {
    new_victim_key = keys[31:16];
    keys[31:16] = key_to_insert;
} 
        r_main_keys.write(h, keys);
    }

    action get_element_from_main_cache_with_lfu(in bit<32> h, in bit<32> index) {
        bit<KEY_SIZE> requested_key = hdr.p4kway.k;
        bit<(ELEMENT_SIZE * MAIN_CACHE_SIZE)> main_element;

        r_main_cache.read(main_element, h);
        
bit<ELEMENT_SIZE> main_element0 = main_element[47:0];
if (index == 0) {
    if (main_element0[47:32] == requested_key) {
        main_element0[15:0] = main_element0[15:0] + 1;
    }
}

bit<ELEMENT_SIZE> main_element1 = main_element[95:48];
if (index == 1) {
    if (main_element1[47:32] == requested_key) {
        main_element1[15:0] = main_element1[15:0] + 1;
    }
}

        main_element = main_element1 ++ main_element0;
        r_main_cache.write(h, main_element);
    }

    action get_element_from_front_cache_with_lfu(in bit<32> h, in bit<32> index) {
        bit<KEY_SIZE> requested_key = hdr.p4kway.k;
        bit<(ELEMENT_SIZE * FRONT_CACHE_SIZE)> front_element;

        r_front_cache.read(front_element, h);
        
bit<ELEMENT_SIZE> front_element0 = front_element[47:0];
if (index == 0) {
    if (front_element0[47:32] == requested_key) {
        front_element0[15:0] = front_element0[15:0] + 1;
    }
}

bit<ELEMENT_SIZE> front_element1 = front_element[95:48];
if (index == 1) {
    if (front_element1[47:32] == requested_key) {
        front_element1[15:0] = front_element1[15:0] + 1;
    }
}

        front_element = front_element1 ++ front_element0;
        r_front_cache.write(h, front_element);
    }

    action insert_to_lfu_inner(in bit<32> index, in bit<KEY_SIZE> k, in bit<32> c, inout bit<ELEMENT_SIZE> element) {
        bit<ELEMENT_SIZE> victim_element = 0;
        victim_element[47:32] = element[47:32]; //k
        victim_element[31:0] = element[31:0];   //c
        if (victim_element[31:0] > 0) {
            victim_element[31:0] = victim_element[31:0] - 1;
        }
        r_victim_element.write(0, victim_element);

         // Update cache[0] to be the new element 
        element[47:32] = k;
        element[31:0] = c;
    }

    action insert_to_main_cache_with_lfu_first_element(in bit<32> h, in bit<32> index, inout bit<ELEMENT_SIZE> element) {
        bit<KEY_SIZE> requested_key = hdr.p4kway.k;

        insert_to_lfu_inner(index, requested_key, 1, element);

        // Insert the key to the keys_register
        bit<KEY_SIZE> next_victim;
        insert_key_to_main_keys_register(h, index, hdr.p4kway.k, next_victim);
        r_victim_key.write(0, next_victim);
    }

    action insert_to_front_cache_with_lfu_first_element(in bit<32> h, in bit<32> index, inout bit<ELEMENT_SIZE> element) {
        bit<KEY_SIZE> requested_key = hdr.p4kway.k;

        insert_to_lfu_inner(index, requested_key, 1, element);

        // Insert the key to the keys_register
        bit<KEY_SIZE> next_victim;
        insert_key_to_front_keys_register(h, index, hdr.p4kway.k, next_victim);
        r_victim_key.write(0, next_victim);
    }

    action insert_to_main_cache_with_lfu(in bit<32> h, in bit<32> index, inout bit<ELEMENT_SIZE> element) {
        bit<ELEMENT_SIZE> current_victim;
        r_victim_element.read(current_victim, 0);

        insert_to_lfu_inner(index, current_victim[47:32], current_victim[31:0], element);

        // Insert the key to the keys_register
        bit<KEY_SIZE> current_victim_key;
        r_victim_key.read(current_victim_key, 0);

        bit<KEY_SIZE> next_victim_key;
        insert_key_to_main_keys_register(h, index, current_victim_key, next_victim_key);
        r_victim_key.write(0, next_victim_key);
    }

    action insert_to_front_cache_with_lfu(in bit<32> h, in bit<32> index, inout bit<ELEMENT_SIZE> element) {
        bit<ELEMENT_SIZE> current_victim;
        r_victim_element.read(current_victim, 0);

        insert_to_lfu_inner(index, current_victim[47:32], current_victim[31:0], element);

        // Insert the key to the keys_register
        bit<KEY_SIZE> current_victim_key;
        r_victim_key.read(current_victim_key, 0);

        bit<KEY_SIZE> next_victim_key;
        insert_key_to_front_keys_register(h, index, current_victim_key, next_victim_key);
        r_victim_key.write(0, next_victim_key);
    }

    action operation_drop() {
        mark_to_drop(standard_metadata);
    }

    action mark_main_hit() {
	    hdr.p4kway.cache = 1;
    }

    action mark_front_hit() {
	    hdr.p4kway.front = 1;
    }

    action mark_main_miss() {
	    hdr.p4kway.cache = 0;
    }

    action mark_front_miss() {
	    hdr.p4kway.front = 0;
    }

    action skip() { 
        // Do nothing
    }

    table check_main_cache {
        key = {
	        main_keys_mask: ternary;
        }
        actions = {
		    mark_main_hit;
		    mark_main_miss;
        }
        const default_action = mark_main_miss();
        const entries = {
	        32w0x0000FFFF &&& 32w0xFFFF0000: mark_main_hit();
32w0xFFFF0000 &&& 32w0x0000FFFF: mark_main_hit();
        }
    }

    table check_front_cache {
        key = {
	        front_keys_mask: ternary;
        }
        actions = {
		    mark_front_hit;
		    mark_front_miss;
        }
        const default_action = mark_front_miss();
        const entries = {
	        32w0x0000FFFF &&& 32w0xFFFF0000: mark_front_hit();
32w0xFFFF0000 &&& 32w0x0000FFFF: mark_front_hit();
        }
    }

    apply {
        if (hdr.p4kway.isValid()) {

            //Deamorization Process:
            bit<COUNTER_SIZE> counter_value;
            bit<32> current_timestamp;
            r_timestamp.read(current_timestamp, 0);
            
if (current_timestamp == 8) {
    
r_counter.read(counter_value, 0);
counter_value = counter_value << 1;
r_counter.write(0, counter_value);

r_counter.read(counter_value, 1);
counter_value = counter_value << 1;
r_counter.write(1, counter_value);

r_counter.read(counter_value, 2);
counter_value = counter_value << 1;
r_counter.write(2, counter_value);

r_counter.read(counter_value, 3);
counter_value = counter_value << 1;
r_counter.write(3, counter_value);

r_counter.read(counter_value, 4);
counter_value = counter_value << 1;
r_counter.write(4, counter_value);

r_counter.read(counter_value, 5);
counter_value = counter_value << 1;
r_counter.write(5, counter_value);

r_counter.read(counter_value, 6);
counter_value = counter_value << 1;
r_counter.write(6, counter_value);

r_counter.read(counter_value, 7);
counter_value = counter_value << 1;
r_counter.write(7, counter_value);

r_counter.read(counter_value, 8);
counter_value = counter_value << 1;
r_counter.write(8, counter_value);

r_counter.read(counter_value, 9);
counter_value = counter_value << 1;
r_counter.write(9, counter_value);

r_counter.read(counter_value, 10);
counter_value = counter_value << 1;
r_counter.write(10, counter_value);

r_counter.read(counter_value, 11);
counter_value = counter_value << 1;
r_counter.write(11, counter_value);

r_counter.read(counter_value, 12);
counter_value = counter_value << 1;
r_counter.write(12, counter_value);

r_counter.read(counter_value, 13);
counter_value = counter_value << 1;
r_counter.write(13, counter_value);

r_counter.read(counter_value, 14);
counter_value = counter_value << 1;
r_counter.write(14, counter_value);

r_counter.read(counter_value, 15);
counter_value = counter_value << 1;
r_counter.write(15, counter_value);

r_counter.read(counter_value, 16);
counter_value = counter_value << 1;
r_counter.write(16, counter_value);

r_counter.read(counter_value, 17);
counter_value = counter_value << 1;
r_counter.write(17, counter_value);

r_counter.read(counter_value, 18);
counter_value = counter_value << 1;
r_counter.write(18, counter_value);

r_counter.read(counter_value, 19);
counter_value = counter_value << 1;
r_counter.write(19, counter_value);

r_counter.read(counter_value, 20);
counter_value = counter_value << 1;
r_counter.write(20, counter_value);

r_counter.read(counter_value, 21);
counter_value = counter_value << 1;
r_counter.write(21, counter_value);

r_counter.read(counter_value, 22);
counter_value = counter_value << 1;
r_counter.write(22, counter_value);

r_counter.read(counter_value, 23);
counter_value = counter_value << 1;
r_counter.write(23, counter_value);

r_counter.read(counter_value, 24);
counter_value = counter_value << 1;
r_counter.write(24, counter_value);

r_counter.read(counter_value, 25);
counter_value = counter_value << 1;
r_counter.write(25, counter_value);

r_counter.read(counter_value, 26);
counter_value = counter_value << 1;
r_counter.write(26, counter_value);

r_counter.read(counter_value, 27);
counter_value = counter_value << 1;
r_counter.write(27, counter_value);

r_counter.read(counter_value, 28);
counter_value = counter_value << 1;
r_counter.write(28, counter_value);

r_counter.read(counter_value, 29);
counter_value = counter_value << 1;
r_counter.write(29, counter_value);

r_counter.read(counter_value, 30);
counter_value = counter_value << 1;
r_counter.write(30, counter_value);

r_counter.read(counter_value, 31);
counter_value = counter_value << 1;
r_counter.write(31, counter_value);

r_counter.read(counter_value, 32);
counter_value = counter_value << 1;
r_counter.write(32, counter_value);

r_counter.read(counter_value, 33);
counter_value = counter_value << 1;
r_counter.write(33, counter_value);

r_counter.read(counter_value, 34);
counter_value = counter_value << 1;
r_counter.write(34, counter_value);

r_counter.read(counter_value, 35);
counter_value = counter_value << 1;
r_counter.write(35, counter_value);

r_counter.read(counter_value, 36);
counter_value = counter_value << 1;
r_counter.write(36, counter_value);

r_counter.read(counter_value, 37);
counter_value = counter_value << 1;
r_counter.write(37, counter_value);

r_counter.read(counter_value, 38);
counter_value = counter_value << 1;
r_counter.write(38, counter_value);

r_counter.read(counter_value, 39);
counter_value = counter_value << 1;
r_counter.write(39, counter_value);

r_counter.read(counter_value, 40);
counter_value = counter_value << 1;
r_counter.write(40, counter_value);

r_counter.read(counter_value, 41);
counter_value = counter_value << 1;
r_counter.write(41, counter_value);

r_counter.read(counter_value, 42);
counter_value = counter_value << 1;
r_counter.write(42, counter_value);

r_counter.read(counter_value, 43);
counter_value = counter_value << 1;
r_counter.write(43, counter_value);

r_counter.read(counter_value, 44);
counter_value = counter_value << 1;
r_counter.write(44, counter_value);

r_counter.read(counter_value, 45);
counter_value = counter_value << 1;
r_counter.write(45, counter_value);

r_counter.read(counter_value, 46);
counter_value = counter_value << 1;
r_counter.write(46, counter_value);

r_counter.read(counter_value, 47);
counter_value = counter_value << 1;
r_counter.write(47, counter_value);

r_counter.read(counter_value, 48);
counter_value = counter_value << 1;
r_counter.write(48, counter_value);

r_counter.read(counter_value, 49);
counter_value = counter_value << 1;
r_counter.write(49, counter_value);

r_counter.read(counter_value, 50);
counter_value = counter_value << 1;
r_counter.write(50, counter_value);

r_counter.read(counter_value, 51);
counter_value = counter_value << 1;
r_counter.write(51, counter_value);

r_counter.read(counter_value, 52);
counter_value = counter_value << 1;
r_counter.write(52, counter_value);

r_counter.read(counter_value, 53);
counter_value = counter_value << 1;
r_counter.write(53, counter_value);

r_counter.read(counter_value, 54);
counter_value = counter_value << 1;
r_counter.write(54, counter_value);

r_counter.read(counter_value, 55);
counter_value = counter_value << 1;
r_counter.write(55, counter_value);

r_counter.read(counter_value, 56);
counter_value = counter_value << 1;
r_counter.write(56, counter_value);

r_counter.read(counter_value, 57);
counter_value = counter_value << 1;
r_counter.write(57, counter_value);

r_counter.read(counter_value, 58);
counter_value = counter_value << 1;
r_counter.write(58, counter_value);

r_counter.read(counter_value, 59);
counter_value = counter_value << 1;
r_counter.write(59, counter_value);

r_counter.read(counter_value, 60);
counter_value = counter_value << 1;
r_counter.write(60, counter_value);

r_counter.read(counter_value, 61);
counter_value = counter_value << 1;
r_counter.write(61, counter_value);

r_counter.read(counter_value, 62);
counter_value = counter_value << 1;
r_counter.write(62, counter_value);

r_counter.read(counter_value, 63);
counter_value = counter_value << 1;
r_counter.write(63, counter_value);
}

if (current_timestamp == 16) {
    
r_counter.read(counter_value, 64);
counter_value = counter_value << 1;
r_counter.write(64, counter_value);

r_counter.read(counter_value, 65);
counter_value = counter_value << 1;
r_counter.write(65, counter_value);

r_counter.read(counter_value, 66);
counter_value = counter_value << 1;
r_counter.write(66, counter_value);

r_counter.read(counter_value, 67);
counter_value = counter_value << 1;
r_counter.write(67, counter_value);

r_counter.read(counter_value, 68);
counter_value = counter_value << 1;
r_counter.write(68, counter_value);

r_counter.read(counter_value, 69);
counter_value = counter_value << 1;
r_counter.write(69, counter_value);

r_counter.read(counter_value, 70);
counter_value = counter_value << 1;
r_counter.write(70, counter_value);

r_counter.read(counter_value, 71);
counter_value = counter_value << 1;
r_counter.write(71, counter_value);

r_counter.read(counter_value, 72);
counter_value = counter_value << 1;
r_counter.write(72, counter_value);

r_counter.read(counter_value, 73);
counter_value = counter_value << 1;
r_counter.write(73, counter_value);

r_counter.read(counter_value, 74);
counter_value = counter_value << 1;
r_counter.write(74, counter_value);

r_counter.read(counter_value, 75);
counter_value = counter_value << 1;
r_counter.write(75, counter_value);

r_counter.read(counter_value, 76);
counter_value = counter_value << 1;
r_counter.write(76, counter_value);

r_counter.read(counter_value, 77);
counter_value = counter_value << 1;
r_counter.write(77, counter_value);

r_counter.read(counter_value, 78);
counter_value = counter_value << 1;
r_counter.write(78, counter_value);

r_counter.read(counter_value, 79);
counter_value = counter_value << 1;
r_counter.write(79, counter_value);

r_counter.read(counter_value, 80);
counter_value = counter_value << 1;
r_counter.write(80, counter_value);

r_counter.read(counter_value, 81);
counter_value = counter_value << 1;
r_counter.write(81, counter_value);

r_counter.read(counter_value, 82);
counter_value = counter_value << 1;
r_counter.write(82, counter_value);

r_counter.read(counter_value, 83);
counter_value = counter_value << 1;
r_counter.write(83, counter_value);

r_counter.read(counter_value, 84);
counter_value = counter_value << 1;
r_counter.write(84, counter_value);

r_counter.read(counter_value, 85);
counter_value = counter_value << 1;
r_counter.write(85, counter_value);

r_counter.read(counter_value, 86);
counter_value = counter_value << 1;
r_counter.write(86, counter_value);

r_counter.read(counter_value, 87);
counter_value = counter_value << 1;
r_counter.write(87, counter_value);

r_counter.read(counter_value, 88);
counter_value = counter_value << 1;
r_counter.write(88, counter_value);

r_counter.read(counter_value, 89);
counter_value = counter_value << 1;
r_counter.write(89, counter_value);

r_counter.read(counter_value, 90);
counter_value = counter_value << 1;
r_counter.write(90, counter_value);

r_counter.read(counter_value, 91);
counter_value = counter_value << 1;
r_counter.write(91, counter_value);

r_counter.read(counter_value, 92);
counter_value = counter_value << 1;
r_counter.write(92, counter_value);

r_counter.read(counter_value, 93);
counter_value = counter_value << 1;
r_counter.write(93, counter_value);

r_counter.read(counter_value, 94);
counter_value = counter_value << 1;
r_counter.write(94, counter_value);

r_counter.read(counter_value, 95);
counter_value = counter_value << 1;
r_counter.write(95, counter_value);

r_counter.read(counter_value, 96);
counter_value = counter_value << 1;
r_counter.write(96, counter_value);

r_counter.read(counter_value, 97);
counter_value = counter_value << 1;
r_counter.write(97, counter_value);

r_counter.read(counter_value, 98);
counter_value = counter_value << 1;
r_counter.write(98, counter_value);

r_counter.read(counter_value, 99);
counter_value = counter_value << 1;
r_counter.write(99, counter_value);

r_counter.read(counter_value, 100);
counter_value = counter_value << 1;
r_counter.write(100, counter_value);

r_counter.read(counter_value, 101);
counter_value = counter_value << 1;
r_counter.write(101, counter_value);

r_counter.read(counter_value, 102);
counter_value = counter_value << 1;
r_counter.write(102, counter_value);

r_counter.read(counter_value, 103);
counter_value = counter_value << 1;
r_counter.write(103, counter_value);

r_counter.read(counter_value, 104);
counter_value = counter_value << 1;
r_counter.write(104, counter_value);

r_counter.read(counter_value, 105);
counter_value = counter_value << 1;
r_counter.write(105, counter_value);

r_counter.read(counter_value, 106);
counter_value = counter_value << 1;
r_counter.write(106, counter_value);

r_counter.read(counter_value, 107);
counter_value = counter_value << 1;
r_counter.write(107, counter_value);

r_counter.read(counter_value, 108);
counter_value = counter_value << 1;
r_counter.write(108, counter_value);

r_counter.read(counter_value, 109);
counter_value = counter_value << 1;
r_counter.write(109, counter_value);

r_counter.read(counter_value, 110);
counter_value = counter_value << 1;
r_counter.write(110, counter_value);

r_counter.read(counter_value, 111);
counter_value = counter_value << 1;
r_counter.write(111, counter_value);

r_counter.read(counter_value, 112);
counter_value = counter_value << 1;
r_counter.write(112, counter_value);

r_counter.read(counter_value, 113);
counter_value = counter_value << 1;
r_counter.write(113, counter_value);

r_counter.read(counter_value, 114);
counter_value = counter_value << 1;
r_counter.write(114, counter_value);

r_counter.read(counter_value, 115);
counter_value = counter_value << 1;
r_counter.write(115, counter_value);

r_counter.read(counter_value, 116);
counter_value = counter_value << 1;
r_counter.write(116, counter_value);

r_counter.read(counter_value, 117);
counter_value = counter_value << 1;
r_counter.write(117, counter_value);

r_counter.read(counter_value, 118);
counter_value = counter_value << 1;
r_counter.write(118, counter_value);

r_counter.read(counter_value, 119);
counter_value = counter_value << 1;
r_counter.write(119, counter_value);

r_counter.read(counter_value, 120);
counter_value = counter_value << 1;
r_counter.write(120, counter_value);

r_counter.read(counter_value, 121);
counter_value = counter_value << 1;
r_counter.write(121, counter_value);

r_counter.read(counter_value, 122);
counter_value = counter_value << 1;
r_counter.write(122, counter_value);

r_counter.read(counter_value, 123);
counter_value = counter_value << 1;
r_counter.write(123, counter_value);

r_counter.read(counter_value, 124);
counter_value = counter_value << 1;
r_counter.write(124, counter_value);

r_counter.read(counter_value, 125);
counter_value = counter_value << 1;
r_counter.write(125, counter_value);

r_counter.read(counter_value, 126);
counter_value = counter_value << 1;
r_counter.write(126, counter_value);

r_counter.read(counter_value, 127);
counter_value = counter_value << 1;
r_counter.write(127, counter_value);
}

if (current_timestamp == 24) {
    
r_counter.read(counter_value, 128);
counter_value = counter_value << 1;
r_counter.write(128, counter_value);

r_counter.read(counter_value, 129);
counter_value = counter_value << 1;
r_counter.write(129, counter_value);

r_counter.read(counter_value, 130);
counter_value = counter_value << 1;
r_counter.write(130, counter_value);

r_counter.read(counter_value, 131);
counter_value = counter_value << 1;
r_counter.write(131, counter_value);

r_counter.read(counter_value, 132);
counter_value = counter_value << 1;
r_counter.write(132, counter_value);

r_counter.read(counter_value, 133);
counter_value = counter_value << 1;
r_counter.write(133, counter_value);

r_counter.read(counter_value, 134);
counter_value = counter_value << 1;
r_counter.write(134, counter_value);

r_counter.read(counter_value, 135);
counter_value = counter_value << 1;
r_counter.write(135, counter_value);

r_counter.read(counter_value, 136);
counter_value = counter_value << 1;
r_counter.write(136, counter_value);

r_counter.read(counter_value, 137);
counter_value = counter_value << 1;
r_counter.write(137, counter_value);

r_counter.read(counter_value, 138);
counter_value = counter_value << 1;
r_counter.write(138, counter_value);

r_counter.read(counter_value, 139);
counter_value = counter_value << 1;
r_counter.write(139, counter_value);

r_counter.read(counter_value, 140);
counter_value = counter_value << 1;
r_counter.write(140, counter_value);

r_counter.read(counter_value, 141);
counter_value = counter_value << 1;
r_counter.write(141, counter_value);

r_counter.read(counter_value, 142);
counter_value = counter_value << 1;
r_counter.write(142, counter_value);

r_counter.read(counter_value, 143);
counter_value = counter_value << 1;
r_counter.write(143, counter_value);

r_counter.read(counter_value, 144);
counter_value = counter_value << 1;
r_counter.write(144, counter_value);

r_counter.read(counter_value, 145);
counter_value = counter_value << 1;
r_counter.write(145, counter_value);

r_counter.read(counter_value, 146);
counter_value = counter_value << 1;
r_counter.write(146, counter_value);

r_counter.read(counter_value, 147);
counter_value = counter_value << 1;
r_counter.write(147, counter_value);

r_counter.read(counter_value, 148);
counter_value = counter_value << 1;
r_counter.write(148, counter_value);

r_counter.read(counter_value, 149);
counter_value = counter_value << 1;
r_counter.write(149, counter_value);

r_counter.read(counter_value, 150);
counter_value = counter_value << 1;
r_counter.write(150, counter_value);

r_counter.read(counter_value, 151);
counter_value = counter_value << 1;
r_counter.write(151, counter_value);

r_counter.read(counter_value, 152);
counter_value = counter_value << 1;
r_counter.write(152, counter_value);

r_counter.read(counter_value, 153);
counter_value = counter_value << 1;
r_counter.write(153, counter_value);

r_counter.read(counter_value, 154);
counter_value = counter_value << 1;
r_counter.write(154, counter_value);

r_counter.read(counter_value, 155);
counter_value = counter_value << 1;
r_counter.write(155, counter_value);

r_counter.read(counter_value, 156);
counter_value = counter_value << 1;
r_counter.write(156, counter_value);

r_counter.read(counter_value, 157);
counter_value = counter_value << 1;
r_counter.write(157, counter_value);

r_counter.read(counter_value, 158);
counter_value = counter_value << 1;
r_counter.write(158, counter_value);

r_counter.read(counter_value, 159);
counter_value = counter_value << 1;
r_counter.write(159, counter_value);

r_counter.read(counter_value, 160);
counter_value = counter_value << 1;
r_counter.write(160, counter_value);

r_counter.read(counter_value, 161);
counter_value = counter_value << 1;
r_counter.write(161, counter_value);

r_counter.read(counter_value, 162);
counter_value = counter_value << 1;
r_counter.write(162, counter_value);

r_counter.read(counter_value, 163);
counter_value = counter_value << 1;
r_counter.write(163, counter_value);

r_counter.read(counter_value, 164);
counter_value = counter_value << 1;
r_counter.write(164, counter_value);

r_counter.read(counter_value, 165);
counter_value = counter_value << 1;
r_counter.write(165, counter_value);

r_counter.read(counter_value, 166);
counter_value = counter_value << 1;
r_counter.write(166, counter_value);

r_counter.read(counter_value, 167);
counter_value = counter_value << 1;
r_counter.write(167, counter_value);

r_counter.read(counter_value, 168);
counter_value = counter_value << 1;
r_counter.write(168, counter_value);

r_counter.read(counter_value, 169);
counter_value = counter_value << 1;
r_counter.write(169, counter_value);

r_counter.read(counter_value, 170);
counter_value = counter_value << 1;
r_counter.write(170, counter_value);

r_counter.read(counter_value, 171);
counter_value = counter_value << 1;
r_counter.write(171, counter_value);

r_counter.read(counter_value, 172);
counter_value = counter_value << 1;
r_counter.write(172, counter_value);

r_counter.read(counter_value, 173);
counter_value = counter_value << 1;
r_counter.write(173, counter_value);

r_counter.read(counter_value, 174);
counter_value = counter_value << 1;
r_counter.write(174, counter_value);

r_counter.read(counter_value, 175);
counter_value = counter_value << 1;
r_counter.write(175, counter_value);

r_counter.read(counter_value, 176);
counter_value = counter_value << 1;
r_counter.write(176, counter_value);

r_counter.read(counter_value, 177);
counter_value = counter_value << 1;
r_counter.write(177, counter_value);

r_counter.read(counter_value, 178);
counter_value = counter_value << 1;
r_counter.write(178, counter_value);

r_counter.read(counter_value, 179);
counter_value = counter_value << 1;
r_counter.write(179, counter_value);

r_counter.read(counter_value, 180);
counter_value = counter_value << 1;
r_counter.write(180, counter_value);

r_counter.read(counter_value, 181);
counter_value = counter_value << 1;
r_counter.write(181, counter_value);

r_counter.read(counter_value, 182);
counter_value = counter_value << 1;
r_counter.write(182, counter_value);

r_counter.read(counter_value, 183);
counter_value = counter_value << 1;
r_counter.write(183, counter_value);

r_counter.read(counter_value, 184);
counter_value = counter_value << 1;
r_counter.write(184, counter_value);

r_counter.read(counter_value, 185);
counter_value = counter_value << 1;
r_counter.write(185, counter_value);

r_counter.read(counter_value, 186);
counter_value = counter_value << 1;
r_counter.write(186, counter_value);

r_counter.read(counter_value, 187);
counter_value = counter_value << 1;
r_counter.write(187, counter_value);

r_counter.read(counter_value, 188);
counter_value = counter_value << 1;
r_counter.write(188, counter_value);

r_counter.read(counter_value, 189);
counter_value = counter_value << 1;
r_counter.write(189, counter_value);

r_counter.read(counter_value, 190);
counter_value = counter_value << 1;
r_counter.write(190, counter_value);

r_counter.read(counter_value, 191);
counter_value = counter_value << 1;
r_counter.write(191, counter_value);
}

if (current_timestamp == 32) {
    
r_counter.read(counter_value, 192);
counter_value = counter_value << 1;
r_counter.write(192, counter_value);

r_counter.read(counter_value, 193);
counter_value = counter_value << 1;
r_counter.write(193, counter_value);

r_counter.read(counter_value, 194);
counter_value = counter_value << 1;
r_counter.write(194, counter_value);

r_counter.read(counter_value, 195);
counter_value = counter_value << 1;
r_counter.write(195, counter_value);

r_counter.read(counter_value, 196);
counter_value = counter_value << 1;
r_counter.write(196, counter_value);

r_counter.read(counter_value, 197);
counter_value = counter_value << 1;
r_counter.write(197, counter_value);

r_counter.read(counter_value, 198);
counter_value = counter_value << 1;
r_counter.write(198, counter_value);

r_counter.read(counter_value, 199);
counter_value = counter_value << 1;
r_counter.write(199, counter_value);

r_counter.read(counter_value, 200);
counter_value = counter_value << 1;
r_counter.write(200, counter_value);

r_counter.read(counter_value, 201);
counter_value = counter_value << 1;
r_counter.write(201, counter_value);

r_counter.read(counter_value, 202);
counter_value = counter_value << 1;
r_counter.write(202, counter_value);

r_counter.read(counter_value, 203);
counter_value = counter_value << 1;
r_counter.write(203, counter_value);

r_counter.read(counter_value, 204);
counter_value = counter_value << 1;
r_counter.write(204, counter_value);

r_counter.read(counter_value, 205);
counter_value = counter_value << 1;
r_counter.write(205, counter_value);

r_counter.read(counter_value, 206);
counter_value = counter_value << 1;
r_counter.write(206, counter_value);

r_counter.read(counter_value, 207);
counter_value = counter_value << 1;
r_counter.write(207, counter_value);

r_counter.read(counter_value, 208);
counter_value = counter_value << 1;
r_counter.write(208, counter_value);

r_counter.read(counter_value, 209);
counter_value = counter_value << 1;
r_counter.write(209, counter_value);

r_counter.read(counter_value, 210);
counter_value = counter_value << 1;
r_counter.write(210, counter_value);

r_counter.read(counter_value, 211);
counter_value = counter_value << 1;
r_counter.write(211, counter_value);

r_counter.read(counter_value, 212);
counter_value = counter_value << 1;
r_counter.write(212, counter_value);

r_counter.read(counter_value, 213);
counter_value = counter_value << 1;
r_counter.write(213, counter_value);

r_counter.read(counter_value, 214);
counter_value = counter_value << 1;
r_counter.write(214, counter_value);

r_counter.read(counter_value, 215);
counter_value = counter_value << 1;
r_counter.write(215, counter_value);

r_counter.read(counter_value, 216);
counter_value = counter_value << 1;
r_counter.write(216, counter_value);

r_counter.read(counter_value, 217);
counter_value = counter_value << 1;
r_counter.write(217, counter_value);

r_counter.read(counter_value, 218);
counter_value = counter_value << 1;
r_counter.write(218, counter_value);

r_counter.read(counter_value, 219);
counter_value = counter_value << 1;
r_counter.write(219, counter_value);

r_counter.read(counter_value, 220);
counter_value = counter_value << 1;
r_counter.write(220, counter_value);

r_counter.read(counter_value, 221);
counter_value = counter_value << 1;
r_counter.write(221, counter_value);

r_counter.read(counter_value, 222);
counter_value = counter_value << 1;
r_counter.write(222, counter_value);

r_counter.read(counter_value, 223);
counter_value = counter_value << 1;
r_counter.write(223, counter_value);

r_counter.read(counter_value, 224);
counter_value = counter_value << 1;
r_counter.write(224, counter_value);

r_counter.read(counter_value, 225);
counter_value = counter_value << 1;
r_counter.write(225, counter_value);

r_counter.read(counter_value, 226);
counter_value = counter_value << 1;
r_counter.write(226, counter_value);

r_counter.read(counter_value, 227);
counter_value = counter_value << 1;
r_counter.write(227, counter_value);

r_counter.read(counter_value, 228);
counter_value = counter_value << 1;
r_counter.write(228, counter_value);

r_counter.read(counter_value, 229);
counter_value = counter_value << 1;
r_counter.write(229, counter_value);

r_counter.read(counter_value, 230);
counter_value = counter_value << 1;
r_counter.write(230, counter_value);

r_counter.read(counter_value, 231);
counter_value = counter_value << 1;
r_counter.write(231, counter_value);

r_counter.read(counter_value, 232);
counter_value = counter_value << 1;
r_counter.write(232, counter_value);

r_counter.read(counter_value, 233);
counter_value = counter_value << 1;
r_counter.write(233, counter_value);

r_counter.read(counter_value, 234);
counter_value = counter_value << 1;
r_counter.write(234, counter_value);

r_counter.read(counter_value, 235);
counter_value = counter_value << 1;
r_counter.write(235, counter_value);

r_counter.read(counter_value, 236);
counter_value = counter_value << 1;
r_counter.write(236, counter_value);

r_counter.read(counter_value, 237);
counter_value = counter_value << 1;
r_counter.write(237, counter_value);

r_counter.read(counter_value, 238);
counter_value = counter_value << 1;
r_counter.write(238, counter_value);

r_counter.read(counter_value, 239);
counter_value = counter_value << 1;
r_counter.write(239, counter_value);

r_counter.read(counter_value, 240);
counter_value = counter_value << 1;
r_counter.write(240, counter_value);

r_counter.read(counter_value, 241);
counter_value = counter_value << 1;
r_counter.write(241, counter_value);

r_counter.read(counter_value, 242);
counter_value = counter_value << 1;
r_counter.write(242, counter_value);

r_counter.read(counter_value, 243);
counter_value = counter_value << 1;
r_counter.write(243, counter_value);

r_counter.read(counter_value, 244);
counter_value = counter_value << 1;
r_counter.write(244, counter_value);

r_counter.read(counter_value, 245);
counter_value = counter_value << 1;
r_counter.write(245, counter_value);

r_counter.read(counter_value, 246);
counter_value = counter_value << 1;
r_counter.write(246, counter_value);

r_counter.read(counter_value, 247);
counter_value = counter_value << 1;
r_counter.write(247, counter_value);

r_counter.read(counter_value, 248);
counter_value = counter_value << 1;
r_counter.write(248, counter_value);

r_counter.read(counter_value, 249);
counter_value = counter_value << 1;
r_counter.write(249, counter_value);

r_counter.read(counter_value, 250);
counter_value = counter_value << 1;
r_counter.write(250, counter_value);

r_counter.read(counter_value, 251);
counter_value = counter_value << 1;
r_counter.write(251, counter_value);

r_counter.read(counter_value, 252);
counter_value = counter_value << 1;
r_counter.write(252, counter_value);

r_counter.read(counter_value, 253);
counter_value = counter_value << 1;
r_counter.write(253, counter_value);

r_counter.read(counter_value, 254);
counter_value = counter_value << 1;
r_counter.write(254, counter_value);

r_counter.read(counter_value, 255);
counter_value = counter_value << 1;
r_counter.write(255, counter_value);
}

            if (current_timestamp == 32) {
                current_timestamp = 0;
            } else {
                current_timestamp = current_timestamp + 1;
            }
            r_timestamp.write(0, current_timestamp);
            
            r_counter.read(counter_value, (bit<32>)hdr.p4kway.k);
            counter_value = counter_value + 1;
            r_counter.write((bit<32>)hdr.p4kway.k, counter_value);
            

            bit<32> h = (bit<32>)hdr.p4kway.k % MAX_ENTRIES;
            r_front_keys.read(front_keys_bit, h);
            r_main_keys.read(main_keys_bit, h);
            front_keys_mask = (hdr.p4kway.k ++ hdr.p4kway.k) ^ front_keys_bit;
            main_keys_mask = (hdr.p4kway.k ++ hdr.p4kway.k) ^ main_keys_bit;

            check_main_cache.apply();
            check_front_cache.apply();
            
            if (hdr.p4kway.cache == 1) {
                // Retrieve from main cache
                get_element_from_main_cache_with_lfu(h ,0);
get_element_from_main_cache_with_lfu(h ,1);

            } else if (hdr.p4kway.front == 1) {
                // Retrieve from front cache
                get_element_from_front_cache_with_lfu(h ,0);
get_element_from_front_cache_with_lfu(h ,1);

            } else {
                bit<ELEMENT_SIZE> current_victim = 0;

                // Insert to front cache
                bit<(ELEMENT_SIZE * FRONT_CACHE_SIZE)> front_element;
                r_front_cache.read(front_element, h);

                bit<ELEMENT_SIZE> front_element0 = front_element[47:0];
                insert_to_front_cache_with_lfu_first_element(h, 0, front_element0);

                
bit<ELEMENT_SIZE> front_element1 = front_element[95:48];
r_victim_element.read(current_victim, 0);
if (hdr.p4kway.front_type == P4GET_VAL_LFU && front_element1[15:0] > current_victim[15:0]) {
    if (front_element1[15:0] > 0) {
        front_element1[15:0] = front_element1[15:0] - 1;
    }
} else {
    insert_to_front_cache_with_lfu(h, 1, front_element1);
}

                front_element = front_element1 ++ front_element0;
                r_front_cache.write(h, front_element);

                r_victim_element.read(current_victim, 0);
                if (current_victim[47:32] != 0) {
                    bit<(ELEMENT_SIZE * MAIN_CACHE_SIZE)> main_element;
                    r_main_cache.read(main_element, h);     
                    
bit<ELEMENT_SIZE> main_element0 = main_element[47:0];
r_victim_element.read(current_victim, 0);
if (hdr.p4kway.main_type == P4GET_VAL_LFU && main_element0[15:0] > current_victim[15:0]) {
    if (main_element0[15:0] > 0) {
        main_element0[15:0] = main_element0[15:0] - 1;
    }
} else {
    insert_to_main_cache_with_lfu(h, 0, main_element0);
}

bit<ELEMENT_SIZE> main_element1 = main_element[95:48];
r_victim_element.read(current_victim, 0);
if (hdr.p4kway.main_type == P4GET_VAL_LFU && main_element1[15:0] > current_victim[15:0]) {
    if (main_element1[15:0] > 0) {
        main_element1[15:0] = main_element1[15:0] - 1;
    }
} else {
    insert_to_main_cache_with_lfu(h, 1, main_element1);
}

                    // Check our filter mechanism - whether the victim from the main cache should really be evicted
                    // or the key from the front cache shouldn't be moved to the main cache at all 
                    r_victim_element.read(current_victim, 0);
                    r_main_keys.read(main_keys_bit, h);
                    if (current_victim[47:32] != 0) {
                        bit<COUNTER_SIZE> first_counter;
                        r_counter.read(first_counter, (bit<32>)current_victim[47:32]);
                        bit<COUNTER_SIZE> second_counter;
                        r_counter.read(second_counter, (bit<32>)main_element0[47:32]);
                        if (second_counter < first_counter) {
                            // Our insertion was incorrect
                            main_element0 = current_victim;
                            main_keys_bit[15:0] = current_victim[47:32];
                        }
                    }
                    r_main_keys.write(h, main_keys_bit);

                    main_element = main_element1 ++ main_element0;
                    r_main_cache.write(h, main_element);
                }    
            }
            send_back();
        } else {
            operation_drop();
        }
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.p4kway);
    }
}

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
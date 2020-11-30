from jinja2 import Template

P4_TEMPLATE = Template('''
#include <core.p4>
#include <v1model.p4>

#define MAX_ENTRIES {{max_entries_size}}
#define MAIN_CACHE_SIZE {{main_cache_size}}
#define FRONT_CACHE_SIZE {{front_cache_size}}
#define ELEMENT_SIZE 48
#define KEY_SIZE {{key_size}}
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

    register<bit<(COUNTER_SIZE)>>({{2 ** key_size - 1}}) r_counter;
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
        {{insert_key_to_front}}
        r_front_keys.write(h, keys);
    }

    action insert_key_to_main_keys_register(in bit<32> h, in bit<32> index, in bit<KEY_SIZE> key_to_insert, out bit<KEY_SIZE> new_victim_key) {
        bit<(KEY_SIZE * MAIN_CACHE_SIZE)> keys;
        r_main_keys.read(keys, h);
        {{insert_key_to_main}}
        r_main_keys.write(h, keys);
    }

    action get_element_from_main_cache_with_lfu(in bit<32> h, in bit<32> index) {
        bit<KEY_SIZE> requested_key = hdr.p4kway.k;
        bit<(ELEMENT_SIZE * MAIN_CACHE_SIZE)> main_element;

        r_main_cache.read(main_element, h);
        {{get_element_from_main_cache}}

        main_element = {{build_main_element}};
        r_main_cache.write(h, main_element);
    }

    action get_element_from_front_cache_with_lfu(in bit<32> h, in bit<32> index) {
        bit<KEY_SIZE> requested_key = hdr.p4kway.k;
        bit<(ELEMENT_SIZE * FRONT_CACHE_SIZE)> front_element;

        r_front_cache.read(front_element, h);
        {{get_element_from_front_cache}}

        front_element = {{build_front_element}};
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
	        {{tcam_main_cache}}
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
	        {{tcam_front_cache}}
        }
    }

    apply {
        if (hdr.p4kway.isValid()) {

            //Deamorization Process:
            bit<COUNTER_SIZE> counter_value;
            bit<32> current_timestamp;
            r_timestamp.read(current_timestamp, 0);
            {{deamortization}}
            if (current_timestamp == {{max_turns}}) {
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
            front_keys_mask = ({{front_keys_mask}}) ^ front_keys_bit;
            main_keys_mask = ({{main_keys_mask}}) ^ main_keys_bit;

            check_main_cache.apply();
            check_front_cache.apply();
            
            if (hdr.p4kway.cache == 1) {
                // Retrieve from main cache
                {{retrieve_from_main_cache}}

            } else if (hdr.p4kway.front == 1) {
                // Retrieve from front cache
                {{retrieve_from_front_cache}}

            } else {
                bit<ELEMENT_SIZE> current_victim = 0;

                // Insert to front cache
                bit<(ELEMENT_SIZE * FRONT_CACHE_SIZE)> front_element;
                r_front_cache.read(front_element, h);

                bit<ELEMENT_SIZE> front_element0 = front_element[47:0];
                insert_to_front_cache_with_lfu_first_element(h, 0, front_element0);

                {{front_actions}}

                front_element = {{build_front_element}};
                r_front_cache.write(h, front_element);

                r_victim_element.read(current_victim, 0);
                if (current_victim[47:32] != 0) {
                    bit<(ELEMENT_SIZE * MAIN_CACHE_SIZE)> main_element;
                    r_main_cache.read(main_element, h);     
                    {{main_actions}}

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

                    main_element = {{build_main_element}};
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
''')


MAIN_ACTION_TEMPLATE = Template('''
bit<ELEMENT_SIZE> {{type}}_element{{i}} = {{type}}_element[{{48*(i+1)-1}}:{{48*i}}];
r_victim_element.read(current_victim, 0);
if (hdr.p4kway.{{type}}_type == P4GET_VAL_LFU && {{type}}_element{{i}}[15:0] > current_victim[15:0]) {
    if ({{type}}_element{{i}}[15:0] > 0) {
        {{type}}_element{{i}}[15:0] = {{type}}_element{{i}}[15:0] - 1;
    }
} else {
    insert_to_{{type}}_cache_with_lfu(h, {{i}}, {{type}}_element{{i}});
}
''')

RETREIVE_FROM_CACHE_TEMPLATE = Template('''get_element_from_{{type}}_cache_with_lfu(h ,{{i}});''')
BUILD_ELEMENT_TEMPLATE = Template('''{{type}}_element{{i}}''')
GET_ELEMENT_FROM_CACHE_TEMPLATE = Template('''
bit<ELEMENT_SIZE> {{type}}_element{{i}} = {{type}}_element[{{48*(i+1)-1}}:{{48*i}}];
if (index == {{i}}) {
    if ({{type}}_element{{i}}[47:32] == requested_key) {
        {{type}}_element{{i}}[15:0] = {{type}}_element{{i}}[15:0] + 1;
    }
}
''')


DEAMORTIZATION_PROCESS_TEMPLATE = Template('''
if (current_timestamp == {{8 * (i+1)}}) {
    {{deamortization_inner}}
}
''')

DEAMORTIZATION_INNER_TEMPLATE = Template('''
r_counter.read(counter_value, {{i}});
counter_value = counter_value << 1;
r_counter.write({{i}}, counter_value);
''')

def get_first_mask(size, index):
    mask = ['FFFF'] * size
    mask[index] = '0000'
    return ''.join(mask)

def get_second_mask(size, index):
    mask = ['0000'] * size
    mask[index] = 'FFFF'
    return ''.join(mask)

TCAM_TEMPLATE = Template('''{{16 * cache_size}}w0x{{get_first_mask(cache_size, i)}} &&& {{16 * cache_size}}w0x{{get_second_mask(cache_size, i)}}: mark_{{type}}_hit();''')

INSERT_KEY_TO_KEY_REGISTER = Template('''
if (index == {{i}}) {
    new_victim_key = keys[{{16*(i+1)-1}}:{{16*i}}];
    keys[{{16*(i+1)-1}}:{{16*i}}] = key_to_insert;
} 
''')


if __name__ == "__main__":
    max_entries_size = 2
    main_cache_size = 2
    front_cache_size = 2
    key_size = 16
    
    main_actions = '\n'.join(list(map(lambda x: MAIN_ACTION_TEMPLATE.render(i=x, type="main"), range(main_cache_size))))
    front_actions = '\n'.join(list(map(lambda x: MAIN_ACTION_TEMPLATE.render(i=x, type="front"), range(1, front_cache_size))))
    
    retrive_from_main_cache = '\n'.join(list(map(lambda x: RETREIVE_FROM_CACHE_TEMPLATE.render(i=x, type="main"), range(main_cache_size))))
    retrive_from_front_cache = '\n'.join(list(map(lambda x: RETREIVE_FROM_CACHE_TEMPLATE.render(i=x, type="front"), range(front_cache_size))))
    
    build_main_element = ' ++ '.join(list(map(lambda x: BUILD_ELEMENT_TEMPLATE.render(i=x,  type="main"), reversed(range(main_cache_size)))))
    build_front_element = ' ++ '.join(list(map(lambda x: BUILD_ELEMENT_TEMPLATE.render(i=x, type="front"), reversed(range(front_cache_size)))))
    
    main_keys_mask = ' ++ '.join(['hdr.p4kway.k'] * main_cache_size)
    front_keys_mask = ' ++ '.join(['hdr.p4kway.k'] * front_cache_size)

    TCAM_TEMPLATE.globals['get_first_mask'] = get_first_mask
    TCAM_TEMPLATE.globals['get_second_mask'] = get_second_mask
    tcam_main_cache = '\n'.join(list(map(lambda x: TCAM_TEMPLATE.render(i=x, cache_size=main_cache_size, type="main"), range(main_cache_size))))
    tcam_front_cache = '\n'.join(list(map(lambda x: TCAM_TEMPLATE.render(i=x, cache_size=front_cache_size, type="front"), range(front_cache_size))))
    
    get_element_from_main_cache = '\n'.join(list(map(lambda x: GET_ELEMENT_FROM_CACHE_TEMPLATE.render(i=x, type="main"), range(main_cache_size))))
    get_element_from_front_cache = '\n'.join(list(map(lambda x: GET_ELEMENT_FROM_CACHE_TEMPLATE.render(i=x, type="front"), range(front_cache_size))))
    
    insert_key_to_main = '\n'.join(list(map(lambda x: INSERT_KEY_TO_KEY_REGISTER.render(i=x), range(main_cache_size))))
    insert_key_to_front = '\n'.join(list(map(lambda x: INSERT_KEY_TO_KEY_REGISTER.render(i=x), range(front_cache_size))))

    deamortization = ''
    max_rounds_until_deamortization = max_entries_size * main_cache_size
    size_of_each_deamortization = int((2 ** (key_size/2) / max_rounds_until_deamortization))

    for i in range(max_rounds_until_deamortization):
        deamortzation_inner = '\n'.join(list(map(lambda x: DEAMORTIZATION_INNER_TEMPLATE.render(i=x), range(i * size_of_each_deamortization, (i+1) * size_of_each_deamortization))))
        deamortization += DEAMORTIZATION_PROCESS_TEMPLATE.render(i=i, deamortization_inner=deamortzation_inner) + '\n'


    p4_generated_file = (P4_TEMPLATE.render
                        (
                            max_entries_size=max_entries_size,
                            key_size=key_size,          
                            main_cache_size=main_cache_size,
                            max_turns=8*main_cache_size*max_entries_size,
                            front_cache_size=front_cache_size,
                            insert_key_to_main=insert_key_to_main,
                            insert_key_to_front=insert_key_to_front,
                            retrieve_from_main_cache=retrive_from_main_cache,
                            retrieve_from_front_cache=retrive_from_front_cache,
                            main_actions=main_actions,
                            front_actions=front_actions,
                            build_main_element=build_main_element,
                            build_front_element=build_front_element,
                            main_keys_mask=main_keys_mask,
                            front_keys_mask=front_keys_mask,
                            tcam_main_cache=tcam_main_cache,
                            tcam_front_cache=tcam_front_cache,
                            get_element_from_main_cache=get_element_from_main_cache,
                            get_element_from_front_cache=get_element_from_front_cache,
                            deamortization=deamortization
                        )
            )

    # print(p4_generated_file)

    with open('/home/dor/dev/PKache/src/pKway-tcam-multi/cahceway.p4', 'w') as f:
        f.write(p4_generated_file)
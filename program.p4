/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/* CONSTANTS */

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_ICMP  = 1;
const bit<8>  TYPE_TCP  = 6;
const bit<8>  TYPE_UDP  = 17;
const bit<16> MAX_REQUESTS = 5000;
const bit<48> TIME_WINDOW = 1000000;
const bit<32> REGISTER_SIZE = 4096;
const bit<48> TIMEOUT = 30000000;
const bit<48> TIMEOUT_NAT = 600000000;
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<16> port_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t{
    port_t srcPort;
    port_t dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<1>  ns;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

header icmp_t {
    bit<8>  type;
    bit<8>  code;          
    bit<16> checksum;      
    bit<16> identifier;    
    bit<16> sequence; 
}
header icmp_payload_t {
    varbit<448> data;
}

struct metadata {
    bool is_blocked;
    bit<16> tcp_length;
    bit<16> icmp_payload_length;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
    udp_t        udp;
    icmp_t       icmp;
    icmp_payload_t icmp_payload;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            TYPE_ICMP: parse_icmp;
            TYPE_TCP: parse_tcp;
            TYPE_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
       packet.extract(hdr.tcp);
       transition accept;
    }

    state parse_udp {
       packet.extract(hdr.udp);
       transition accept;
    }

    state parse_icmp {
       packet.extract(hdr.icmp);
       meta.icmp_payload_length = hdr.ipv4.totalLen - (bit<16>)(hdr.ipv4.ihl) * 4 - 8;
       packet.extract(hdr.icmp_payload, (bit<32>)meta.icmp_payload_length * 8);
       transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    register<bit<16>>(REGISTER_SIZE) request_count;
    register<bit<48>>(REGISTER_SIZE) last_request_time;
    register<bit<48>>(REGISTER_SIZE) block_time;
    register<bit<16>>(1) next_port;
    register<bit<16>>(16384) port_register;
    register<bit<48>>(16384) port_register_time;
    register<bit<16>>(16384) port_register_reverse;
    register<bit<32>>(16384) ip_register_reverse;
    register<bit<32>>(16384) ip_register_icmp;
    register<bit<2>>(REGISTER_SIZE) fin_count;
    
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action check_rate_limit(bit<32> index, bit<48> current_time) {
        bit<16> count;
        bit<48> last_time;
        request_count.read(count, index);
        last_request_time.read(last_time, index);
        if (current_time - last_time > TIME_WINDOW) {
            count = 0;
        }
        count = count + 1;
        request_count.write(index, count);
        last_request_time.write(index, current_time);
        meta.is_blocked = (count > MAX_REQUESTS);
    }

    table tcp_filter_in {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
            hdr.tcp.dstPort: exact;
        }
        actions = {
            drop;
            NoAction;
        }
        size = 512;
        default_action = NoAction();
    }

    table tcp_filter_out {
        key = {
            hdr.ipv4.srcAddr: lpm;
            hdr.ipv4.dstAddr: exact;
            hdr.tcp.dstPort: exact;
        }
        actions = {
            drop;
            NoAction;
        }
        size = 512;
        default_action = NoAction();
    }

     table udp_filter_in {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
            hdr.udp.dstPort: exact;
        }
        actions = {
            drop;
            NoAction;
        }
        size = 512;
        default_action = NoAction();
    }

    table udp_filter_out {
        key = {
            hdr.ipv4.srcAddr: lpm;
            hdr.ipv4.dstAddr: exact;
            hdr.udp.dstPort: exact;
        }
        actions = {
            drop;
            NoAction;
        }
        size = 512;
        default_action = NoAction();
    }

    action dnat_action(ip4Addr_t ipDstAddr, macAddr_t macDstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = macDstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        hdr.ipv4.dstAddr = ipDstAddr;
    }

    table dnat_table {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            dnat_action;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    action snat_action(ip4Addr_t srcAddr) {
        hdr.ipv4.srcAddr = srcAddr;
    }

    table snat_table {
        key = {
            hdr.ipv4.srcAddr: lpm;
        }
        actions = {
            snat_action;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table post_nat_routing {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
    }

    apply {  
        if (hdr.ipv4.isValid()){
            ipv4_lpm.apply();
                if (standard_metadata.ingress_port == 1) {  
                    if ((hdr.tcp.isValid() && (hdr.tcp.dstPort == 23 || hdr.tcp.dstPort == 22 || hdr.tcp.dstPort == 80 || hdr.tcp.dstPort == 53)) || 
                       (hdr.udp.isValid() && (hdr.udp.dstPort == 53 || hdr.udp.dstPort == 23)) ||
                       (hdr.icmp.isValid() && (hdr.icmp.type == 8))) {
                        dnat_table.apply();
                        if (hdr.tcp.isValid()) {
                            tcp_filter_in.apply();
                            meta.tcp_length = hdr.ipv4.totalLen - (bit<16>)(hdr.ipv4.ihl) * 4;
                        }
                        if (hdr.udp.isValid()) {
                            udp_filter_in.apply();
                            hdr.udp.checksum = 0;
                        }
                    } else {
                            if (hdr.tcp.isValid()) {
                                if (hdr.tcp.syn == 1) {
                                    drop();
                                }
                                bit<16> dstPort;
                                bit<32> index_port;
                                bit<32> ipDstAddr;
                                bit<32> index_fin;
                                bit<2> fin_flags;
                                hash(index_port, HashAlgorithm.crc16, (bit<16>)0, {hdr.tcp.dstPort}, 16w16384);
                                port_register_reverse.read(dstPort, index_port);
                                ip_register_reverse.read(ipDstAddr, index_port);
                                if (dstPort == 0 || ipDstAddr == 0){
                                    drop();
                                }
                                hash(index_fin, HashAlgorithm.crc16, (bit<16>)0, {hdr.tcp.dstPort}, REGISTER_SIZE);
                                fin_count.read(fin_flags, index_fin);
                                if (hdr.tcp.rst == 1 || fin_flags == 2) {
                                    bit<32> index_nat;
                                    hash(index_nat, HashAlgorithm.crc16, (bit<16>)0, {ipDstAddr, dstPort}, 16w16384);
                                    port_register.write(index_nat, 0);
                                    port_register_reverse.write(index_port, 0);
                                    ip_register_reverse.write(index_port, 0);
                                    fin_count.write(index_fin, 0);
                                }
                                if (hdr.tcp.fin == 1) {
                                    fin_count.write(index_fin, fin_flags + 1);
                                }
                                hdr.tcp.dstPort = dstPort;
                                hdr.ipv4.dstAddr = ipDstAddr;
                            }
                            if (hdr.udp.isValid()) {        
                                bit<16> dstPort;
                                bit<32> index_port;
                                bit<32> ipDstAddr;
                                hash(index_port, HashAlgorithm.crc16, (bit<16>)0, {hdr.udp.dstPort}, 16w16384);
                                port_register_reverse.read(dstPort, index_port);
                                ip_register_reverse.read(ipDstAddr, index_port);
                                if (dstPort == 0 || ipDstAddr == 0){
                                    drop();
                                }
                                hdr.udp.dstPort = dstPort;
                                hdr.ipv4.dstAddr = ipDstAddr;
                                hdr.udp.checksum = 0;
                            }
                            if (hdr.icmp.isValid()) {
                                bit<32> index_icmp;
                                bit<32> ipDstAddr;
                                hash(index_icmp, HashAlgorithm.crc16, (bit<16>)0, {hdr.ipv4.srcAddr, hdr.icmp.identifier}, 16w16384);
                                ip_register_icmp.read(ipDstAddr, index_icmp);
                                if (ipDstAddr == 0 ) {
                                    drop();
                                }
                                hdr.ipv4.dstAddr = ipDstAddr;
                            }
                            post_nat_routing.apply();
                            if (hdr.tcp.isValid()) {
                                meta.tcp_length = hdr.ipv4.totalLen - (bit<16>)(hdr.ipv4.ihl) * 4;
                            }
                        }
                }
                if (standard_metadata.egress_spec == 1) {
                    if (hdr.tcp.isValid()) { 
                        if (hdr.tcp.srcPort != 23 && hdr.tcp.srcPort != 22 && hdr.tcp.srcPort != 80 && hdr.tcp.srcPort != 53) {
                            tcp_filter_out.apply();
                            bit<16> port;
                            bit<32> index_nat;
                            bit<48> current_time_nat = standard_metadata.ingress_global_timestamp;
                            bit<48> last_time_nat;
                            bit<32> index_port;
                            bit<32> index_fin;
                            bit<2> fin_flags;
                            hash(index_nat, HashAlgorithm.crc16, (bit<16>)0, {hdr.ipv4.srcAddr, hdr.tcp.srcPort}, 16w16384);
                            port_register.read(port, index_nat);
                            port_register_time.read(last_time_nat, index_nat);
                            if (port == 0 || (current_time_nat - last_time_nat > TIMEOUT_NAT)) {
                                next_port.read(port, 0);
                                if (port == 65535 || port == 0) {
                                    port = 49152;
                                }
                                port_register.write(index_nat, port);
                                next_port.write(0, port + 1);
                                hash(index_port, HashAlgorithm.crc16, (bit<16>)0, {port}, 16w16384);
                                port_register_reverse.write(index_port, hdr.tcp.srcPort);
                                ip_register_reverse.write(index_port, hdr.ipv4.srcAddr);
                            }
                            hdr.tcp.srcPort = port;
                            port_register_time.write(index_nat, current_time_nat);
                            hash(index_fin, HashAlgorithm.crc16, (bit<16>)0, {port}, REGISTER_SIZE);
                            fin_count.read(fin_flags, index_fin);
                            if (hdr.tcp.rst == 1 || fin_flags == 2) {
                                port_register.write(index_nat, 0);
                                hash(index_port, HashAlgorithm.crc16, (bit<16>)0, {port}, 16w16384);
                                port_register_reverse.write(index_port, 0);
                                ip_register_reverse.write(index_port, 0);
                                fin_count.write(index_fin, 0);
                            }
                            if (hdr.tcp.fin == 1) {
                                fin_count.write(index_fin, fin_flags + 1);
                            }
                        }
                    }
                    if (hdr.udp.isValid()) {
                        if (hdr.udp.srcPort != 53 && hdr.udp.srcPort != 23) {
                            udp_filter_out.apply();
                            bit<16> port;
                            bit<32> index_nat;
                            bit<48> current_time_nat = standard_metadata.ingress_global_timestamp;
                            bit<48> last_time_nat;
                            bit<32> index_port;
                            hash(index_nat, HashAlgorithm.crc16, (bit<16>)0, {hdr.ipv4.srcAddr, hdr.udp.srcPort}, 16w16384);
                            port_register.read(port, index_nat);
                            port_register_time.read(last_time_nat, index_nat);
                            if (port == 0 || (current_time_nat - last_time_nat > TIMEOUT_NAT)) {
                                next_port.read(port, 0);
                                if (port == 65535 || port == 0) {
                                    port = 49152;
                                }
                                port_register.write(index_nat, port);
                                next_port.write(0, port + 1);
                                hash(index_port, HashAlgorithm.crc16, (bit<16>)0, {port}, 16w16384);
                                port_register_reverse.write(index_port, hdr.udp.srcPort);
                                ip_register_reverse.write(index_port, hdr.ipv4.srcAddr);
                            }
                            hdr.udp.srcPort = port;
                            port_register_time.write(index_nat, current_time_nat);
                        }
                    }
                    if (hdr.icmp.isValid()) {
                        bit<32> index_icmp;
                        bit<32> ipSrcAddr;
                        hash(index_icmp, HashAlgorithm.crc16, (bit<16>)0, {hdr.ipv4.dstAddr, hdr.icmp.identifier}, 16w16384);
                        ip_register_icmp.read(ipSrcAddr, index_icmp);
                        if (ipSrcAddr == 0 && hdr.icmp.type != 0) {
                            ip_register_icmp.write(index_icmp, hdr.ipv4.srcAddr);
                        }
                    }
                    snat_table.apply();
                    if (hdr.tcp.isValid()) {
                        meta.tcp_length = hdr.ipv4.totalLen - (bit<16>)(hdr.ipv4.ihl) * 4;
                    }
                    if (hdr.udp.isValid()) {
                        hdr.udp.checksum = 0;
                    }
                }
            if (hdr.tcp.isValid() || hdr.udp.isValid() || hdr.icmp.isValid()) {    
                if (standard_metadata.ingress_port == 1) {
                    bit<16> port = 0;
                    bit<32> index;
                    if (hdr.tcp.isValid()) {
                        port = hdr.tcp.dstPort;
                    }
                    if (hdr.udp.isValid()) {
                        port = hdr.udp.dstPort;
                    }
                    if (hdr.icmp.isValid()) {
                        port = hdr.icmp.identifier;
                    }
                    hash(index, HashAlgorithm.crc16, (bit<16>)0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, port}, REGISTER_SIZE);
                    bit<48> current_time = standard_metadata.ingress_global_timestamp;
                    bit<48> block_timestamp;
                    block_time.read(block_timestamp, index);
                    if (block_timestamp != 0) {
                        if (current_time - block_timestamp > TIMEOUT) {
                            block_time.write(index, 0);
                        } else {
                            drop();
                        }
                    } else {
                        meta.is_blocked = false;
                        check_rate_limit(index, current_time);
                        if (meta.is_blocked){
                            block_time.write(index, current_time);
                            drop();
                        }
                    }
                }
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    apply { }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);

        update_checksum_with_payload(
            hdr.tcp.isValid(),
            { 
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr,
              8w0,
              hdr.ipv4.protocol,
              meta.tcp_length,
            
              hdr.tcp.srcPort, 
              hdr.tcp.dstPort,
              hdr.tcp.seqNo,
              hdr.tcp.ackNo,
              hdr.tcp.dataOffset,
              hdr.tcp.res,
              hdr.tcp.ns,
              hdr.tcp.cwr,
              hdr.tcp.ece,
              hdr.tcp.urg,
              hdr.tcp.ack,
              hdr.tcp.psh,
              hdr.tcp.rst,
              hdr.tcp.syn,
              hdr.tcp.fin,
              hdr.tcp.window,
              hdr.tcp.urgentPtr
            },
            hdr.tcp.checksum,
            HashAlgorithm.csum16);
        update_checksum_with_payload(
            hdr.icmp.isValid(),
            { hdr.icmp.type,
              hdr.icmp.code,
              hdr.icmp.identifier,
              hdr.icmp.sequence,
              hdr.icmp_payload },
            hdr.icmp.checksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.icmp);
        packet.emit(hdr.icmp_payload);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
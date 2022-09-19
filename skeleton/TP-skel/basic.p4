/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define INT_TAM_FILHO 13 // Soma dos bits do int_filho (que deve ser múltiplo de 8)
#define INT_TAM_PAI 9 // Soma dos bits do int_pai (que deve ser múltiplo de 8)

#define MAX_FILHOS 80

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TYPE_TCP = 0x06;
const bit<8> TYPE_INT = 0x12; // Based on basic_tunnel example. 

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

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

header int_pai_t {
    bit<32> tam_filho;
    bit<32> qtd_filhos;
    bit<8> next_proto;
}

header int_filho_t{
    bit<32> id_switch;
    bit<9> porta_entrada;
    bit<9> porta_saida;
    bit<48> timestamp;
    // Outros dados
    bit<6> padding;
}

//From load_balance example in class
header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct metadata {
    bit<32> it_filhos; // iterador para os filhos. 
                       // 32 bits porque meta.it_filhos = hdr.int_pai.qtd_filhos 
                       // não funciona por tamanhos serem incompatíveis
}

struct headers {
    ethernet_t                      ethernet;
    ipv4_t                          ipv4;
    //Aditional data
    int_pai_t                       int_pai;
    int_filho_t[MAX_FILHOS]         int_filhos;
    // From load_balance example
    tcp_t                           tcp;
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
        transition select(hdr.ipv4.protocol) {
            TYPE_TCP: parse_tcp;
            TYPE_INT: parse_int_pai;
            default: accept;
        }
    }

    // Based on basic_tunnel and mri example.
    state parse_int_pai {
        packet.extract(hdr.int_pai);
        meta.it_filhos = hdr.int_pai.qtd_filhos;
        transition parse_int_filhos;
    }

    state parse_int_filhos {
        // based on mri example
        packet.extract(hdr.int_filhos.next);
        meta.it_filhos = meta.it_filhos - 1;
        transition select(meta.it_filhos) {
            0 : parse_tcp;
            default: parse_int_filhos;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
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

    register<bit<32>>(1) swid;
    
    action drop() {
        mark_to_drop();
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action add_int_pai(){
        hdr.int_pai.setValid();
        hdr.int_pai.tam_filho = INT_TAM_FILHO;
        hdr.int_pai.qtd_filhos = 0;
        hdr.int_pai.next_proto = TYPE_TCP;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + INT_TAM_PAI;
        hdr.ipv4.protocol = TYPE_INT;
    }

    action add_int_filho(){
        bit<32> var_swid;
        swid.read(var_swid, 0);

        // Contabiliza filho
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + INT_TAM_FILHO;
        hdr.int_pai.qtd_filhos = hdr.int_pai.qtd_filhos + 1;

        hdr.int_filhos.push_front(1);
        // Adicionando dados do filhos
        hdr.int_filhos[0].setValid();
        hdr.int_filhos[0].id_switch = var_swid;
        hdr.int_filhos[0].porta_entrada = standard_metadata.ingress_port;
        hdr.int_filhos[0].porta_saida = standard_metadata.egress_spec;
        hdr.int_filhos[0].timestamp = standard_metadata.ingress_global_timestamp;
        hdr.int_filhos[0].padding = 0;
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
        default_action = drop();
    }
    
    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }

        if(!hdr.int_pai.isValid()){
            add_int_pai();
        }
        
        if(hdr.int_pai.isValid()){
            add_int_filho();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
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
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        // Based on mri example
        packet.emit(hdr.int_pai);
        packet.emit(hdr.int_filhos);
        packet.emit(hdr.tcp);
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

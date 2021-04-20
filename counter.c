#define KBUILD_MODNAME "filter"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>

//struct counter_data {
//    u32 syn_tx;
//    u32 rst_tx;
//    u32 fin_tx;
//    u32 udp_tx;
//    u32 icmp_tx;
//    u32 tcp_tx;
//    u32 packet_rate_tx;
//    u32 throughput_tx;
//};

// per creare una mappa che usa int per maggiore efficienza posso usare un u64 con
// primi 16bit porta dst, secondi 16 bit 0.0.x.x ultimi
// valori dell'ip escludo il prefisso, ipotizzo di usare al masimo una /16,
// ultimi 32bit ip dst
BPF_HISTOGRAM(syn_tx_counter_by_src, u64, 1024);
BPF_HISTOGRAM(rst_tx_counter_by_src, u64, 1024);
BPF_HISTOGRAM(fin_tx_counter_by_src, u64, 1024);
BPF_HISTOGRAM(udp_tx_counter_by_src, u64, 1024);
BPF_HISTOGRAM(icmp_tx_counter_by_src, u64, 1024);
BPF_HISTOGRAM(tcp_tx_counter_by_src, u64, 1024);
BPF_HISTOGRAM(packet_rate_tx_counter_by_src, u64, 1024);
//BPF_HISTOGRAM(throughput_tx_counter_by_src, u64, 1024);

// name, key size, value size, table size
// scegliere un valore ragionevole per la dimensione della tabella
BPF_HASH(blacklist_table, u64, bool, 10240);

static u64 get_map_key(u32 src_ip, u32 dst_ip, u16 dst_port){
    u64 value = dst_ip;
    value += ((u64) (src_ip & 0xFFFF0000) << 16);
    value += ((u64) dst_port << 48);
    return value;
};


int filter(struct xdp_md *ctx) {
//  bpf_trace_printk("ddos filter\n");
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct ethhdr *eth = data;
  if ((void*)eth + sizeof(*eth) <= data_end) {
    struct iphdr *ip = data + sizeof(*eth);
    if ((void*)ip + sizeof(*ip) <= data_end) {
      if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void*)ip + sizeof(*ip);
        if ((void*)udp + sizeof(*udp) <= data_end) {
            u64 key = get_map_key(ip->saddr, ip->daddr, udp->dest);
            packet_rate_tx_counter_by_src.increment(key);
            udp_tx_counter_by_src.increment(key);
//          if (udp->dest == ntohs(7999)) {
//            // bpf_trace_printk("udp port 7999\n");
//            udp->dest = ntohs(7998);
//          }
        }
      }
      if (ip->protocol == IPPROTO_TCP){
        struct tcphdr *tcp = (void*)ip + sizeof(*ip);
        if ((void*)tcp + sizeof(*tcp) <= data_end) {
            u64 key = get_map_key(ip->saddr, ip->daddr, tcp->dest);
            packet_rate_tx_counter_by_src.increment(key);
            tcp_tx_counter_by_src.increment(key);
            if (tcp->syn) {
//                bpf_trace_printk("syn packet: %lx %lx\n", tcp->dest, key);
                syn_tx_counter_by_src.increment(key);
                // sea una delle due chiavi è presente nella blacklist faccio il drop del pacchetto
                // le blacklist sono riempite dall'interfaccia in python ogni x secondi
//                if(blacklist_table.lookup(&key)!=NULL){
//                    bpf_trace_printk("blacklist\n");
//                    return XDP_DROP;
//                }
            }
            else if (tcp->fin) {
//                bpf_trace_printk("fin packet\n");
                fin_tx_counter_by_src.increment(key);
            }
            else if (tcp->rst){
//                bpf_trace_printk("rst packet\n");
                rst_tx_counter_by_src.increment(key);
            }
        }
      }
    }
  }
  return XDP_PASS;
}

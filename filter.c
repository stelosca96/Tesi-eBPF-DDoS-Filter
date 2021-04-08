#define KBUILD_MODNAME "filter"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>


BPF_HISTOGRAM(syn_counter_by_dst, u64, 1024);
BPF_HISTOGRAM(fin_counter_by_dst, u64, 1024);


// per creare una mappa che usa int per maggiore efficienza posso usare un u64 con
// primi 16bit porta dst, secondi 16 bit 0.0.x.x ultimi
// valori dell'ip escludo il prefisso, ipotizzo di usare al masimo una /16,
// ultimi 32bit ip dst
BPF_HISTOGRAM(syn_counter_by_src, u64, 1024);
BPF_HISTOGRAM(fin_counter_by_src, u64, 1024);
BPF_HISTOGRAM(rst_counter_by_src, u64, 1024);

// name, key size, value size, table size
// scegliere un valore ragionevole per la dimensione della tabella
BPF_HASH(blacklist_table, u64, bool, 10240);

static u64 get_map_key_1(u32 dst_ip, u16 dst_port){
    u64 value = dst_ip;
    value += ((u64) dst_port << 48);
    return value;
};

static u64 get_map_key_2(u32 src_ip, u32 dst_ip, u16 dst_port){
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
//      if (ip->protocol == IPPROTO_UDP) {
//        struct udphdr *udp = (void*)ip + sizeof(*ip);
//        if ((void*)udp + sizeof(*udp) <= data_end) {
//          if (udp->dest == ntohs(7999)) {
//            // bpf_trace_printk("udp port 7999\n");
//            udp->dest = ntohs(7998);
//          }
//        }
//      }
      if (ip->protocol == IPPROTO_TCP){
        struct tcphdr *tcp = (void*)ip + sizeof(*ip);
        if ((void*)tcp + sizeof(*tcp) <= data_end) {
          if (tcp->syn) {
            u64 key_1 = get_map_key_1(ip->daddr, tcp->dest);
            syn_counter_by_dst.increment(key_1);
            u64 key_2 = get_map_key_2(ip->saddr, ip->daddr, tcp->dest);
            syn_counter_by_src.increment(key_2);
            bpf_trace_printk("syn packet: %lx %lx\n", tcp->dest, key_2);
            // se una delle due chiavi è presente nella blacklist faccio il drop del pacchetto
            // le blacklist sono riempite dall'interfaccia in python ogni x secondi
            if(blacklist_table.lookup(&key_1)!=NULL || blacklist_table.lookup(&key_2)!=NULL){
                bpf_trace_printk("blacklist\n");
                return XDP_DROP;
            }
          }
          else if (tcp->fin) {
            fin_counter_by_dst.increment(get_map_key_1(ip->daddr, tcp->dest));
            fin_counter_by_src.increment(get_map_key_2(ip->saddr, ip->daddr, tcp->dest));
            bpf_trace_printk("fin packet\n");
          }
          else if (tcp->rst){
            bpf_trace_printk("rst packet\n");
            fin_counter_by_dst.increment(get_map_key_1(ip->daddr, tcp->dest));
            rst_counter_by_src.increment(get_map_key_2(ip->saddr, ip->daddr, tcp->dest));
          }
        }
      }
    }
  }
  return XDP_PASS;
}

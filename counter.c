//#define KBUILD_MODNAME "filter"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>

struct counter_data
{
  u32 syn_tx;
  u32 rst_tx;
  u32 fin_tx;
  u32 udp_tx;
  u32 udp_tx_53;
  u32 icmp_tx;
  u32 tcp_tx;
  u32 packet_rate_tx;
  u32 throughput_tx;
};



// name, key size, value size, table size
// scegliere un valore ragionevole per la dimensione della tabella
BPF_HASH(blacklist_table, u64, bool, 10240);

// per creare una mappa che usa int per maggiore efficienza posso usare un u64 con
// primi 16bit porta dst, secondi 16 bit 0.0.x.x ultimi
// valori dell'ip escludo il prefisso, ipotizzo di usare al masimo una /16,
// ultimi 32bit ip dst
BPF_HASH(counters, u64, struct counter_data, 10240);

static u64 get_map_key(u32 src_ip, u32 dst_ip, u16 dst_port)
{
  u64 value = dst_ip;
  value += ((u64)(src_ip & 0xFFFF0000) << 16);
  value += ((u64)dst_port << 48);
  return value;
};

int filter(struct xdp_md *ctx)
{
  //  bpf_trace_printk("ddos filter\n");
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct ethhdr *eth = data;

  if ((void *)eth + sizeof(*eth) <= data_end)
  {
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) <= data_end)
    {
      struct counter_data zero_counters = {0};
      u64 key = get_map_key(ip->saddr, ip->daddr, 0);
      struct counter_data *val = counters.lookup_or_try_init(&key, &zero_counters);
      if (val){
            val->packet_rate_tx++;
            val->throughput_tx+=ntohs(ip->tot_len);
      }
      if (ip->protocol == IPPROTO_ICMP)
      {
        if (val)
            val->icmp_tx++;
      }
      else if (ip->protocol == IPPROTO_UDP)
      {
        struct udphdr *udp = (void *)ip + sizeof(*ip);
        if ((void *)udp + sizeof(*udp) <= data_end)
        {
          u64 key = get_map_key(ip->saddr, ip->daddr, udp->dest);
          struct counter_data *val = counters.lookup_or_try_init(&key, &zero_counters);
          if (val)
          {
            val->udp_tx++;
            val->throughput_tx+=ntohs(ip->tot_len);
            if (udp->dest == ntohs(53))
            {
              val->udp_tx_53++;
            }
          }
        }
      }
      else if (ip->protocol == IPPROTO_TCP)
      {
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        if ((void *)tcp + sizeof(*tcp) <= data_end)
        {
          u64 key = get_map_key(ip->saddr, ip->daddr, tcp->dest);
          struct counter_data *val = counters.lookup_or_try_init(&key, &zero_counters);
          if (val)
          {
            val->tcp_tx++;
            val->throughput_tx+=ntohs(ip->tot_len);
            if (tcp->syn)
            {
              val->syn_tx++;
            }
            else if (tcp->fin)
            {
              val->fin_tx++;
            }
            else if (tcp->rst)
            {
              val->rst_tx++;
            }
          }
        }
      }
    }
  }
  return XDP_PASS;
}

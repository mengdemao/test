# libcap教程

## 找到网络设备名称

```c
int pcap_findalldevs(pcap_if_t **alldevsp, char *errbuf);
void pcap_freealldevs(pcap_if_t *alldevs);
```

pcap接口描述

```c
struct pcap_if {
	struct pcap_if *next;
	char *name;		/* name to hand to "pcap_open_live()" */
	char *description;	/* textual description of interface, or NULL */
	struct pcap_addr *addresses;
	bpf_u_int32 flags;	/* PCAP_IF_ interface flags */
};
```

## 打开设备
```c
pcap_t *pcap_open_live(const char *device, int snaplen, int promisc, int to_ms, char *errbuf);
```

## 发送
```c
int pcap_inject(pcap_t *p, const void *buf, size_t size);
int pcap_sendpacket(pcap_t *p, const u_char *buf, int size);
```
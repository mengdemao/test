#include <iostream>
#include <pcap.h>
#include <string.h>

using namespace std;

/**
 * @brief 
 * 
 * @return int 
 */
int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *dev = NULL;
	pcap_t *handle = NULL;

	bpf_u_int32 net;
	bpf_u_int32 mask;
	
	struct pcap_pkthdr pkthdr;
    const u_char *packet;
 
	struct bpf_program fp;
	const char filter_text[] = "host 192.168.2.126";
	u_char user[128] = "Hello World";
	(void)argc;
	(void)argv;

	// 初始化pcap库
	if (pcap_init(PCAP_CHAR_ENC_UTF_8, errbuf)) {
		cout << errbuf << endl;
		return -1;
	}

	// 获取网络设备
	if (pcap_findalldevs(&dev, errbuf)) {
		cout << "find all devs" << errbuf << endl;
		goto exit;
	}

	// 打印获取到的网卡设备信息
	for (pcap_if_t *dev_i = dev; NULL != dev_i->next; dev_i = dev_i->next) {
		cout << "netdev \t" << dev_i << " name \t" << dev_i->name << endl;
	}

	// 打开对应的网卡信息
	if (pcap_lookupnet(dev->name, &net, &mask, errbuf) == -1) {
        cout << "couldn't get netmask for device" << dev->name << errbuf << endl;
        net = 0;
        mask = 0;
    }

	// 打开网络设备
    handle = pcap_open_live(dev->name, 65535,1, 1000, errbuf);
	if (!handle) {
		cout << "open live error " << dev->name << " " << errbuf << endl;
		goto exit;
	}
	

exit:
	// 关闭打开的网络设备
	pcap_close(handle);
	// 释放网络设备
	pcap_freealldevs(dev);

	return 0;
}

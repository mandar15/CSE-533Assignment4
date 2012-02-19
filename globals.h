# include "unp.h" 
# include "hw_addrs.h"
# include "netinet/ip.h"
# include "netinet/ip_icmp.h"
# include "linux/if_ether.h"
#include <netpacket/packet.h>
#include <net/ethernet.h> 
#include <net/if_arp.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <setjmp.h>
#include <sys/un.h>

# define IPPROTO_RT 211

# define RT_PORT 4094

# define IPPROTO_ID 9799

//# define ETH_P_IP 0x0800
# define AREQ_FLAG 1

# define TOUR_FLAG 2

# define ETH_FRAME_LEN 1514

# define HW_ADDR_LEN 6

# define MULTICAST_ADDR "228.108.148.108"

# define MULTICAST_PORT 4093

# define BUF_SIZE 100

#define ARP_OP_ARP_REQ 1
#define ARP_OP_ARP_REP 2
#define ARP_OP_RARP_REQ 3
#define ARP_OP_RARP_REP 4

#define ARP_ID 0xad

#define SERVER_PATH "/tmp/group28"

#define trace printf("%s: %d\n", __FILE__, __LINE__)

typedef struct
{
	char src_ip[INET_ADDRSTRLEN];
	int total_nodes;
	int next_node;
	char multicast_ip[INET_ADDRSTRLEN];
	//char multicast_port[sizeof(MULTICAST_PORT)];
	int multicast_port;
}ip_data;

typedef struct
{
    struct in_addr ce_ip_addr;
    unsigned char ce_hw_addr[6];
    int ce_ifindex;
    unsigned short ce_hatype;
    int ce_sockfd;
    int ce_incomplete;
}cache_entry;

struct cache
{
    cache_entry* ar_entry;
    struct cache* ar_next;
};

typedef struct cache ar_cache;

typedef struct 
{
    uint16_t ah_hard_type;
    uint16_t ah_prot_type;
    short ah_hard_size;
    short ah_prot_size;
    uint16_t ah_op;
    unsigned char ah_sender_eth_addr[6];
    struct in_addr ah_sender_ip_addr;
    unsigned char ah_target_eth_addr[6];
    struct in_addr ah_target_ip_addr;
    uint16_t ah_id;
}arp_header;

struct src_dest_info
{
	char src[INET_ADDRSTRLEN];
	char dest[INET_ADDRSTRLEN];
	int pf;
	int pid;
};

struct hwaddr
{
    int sll_ifindex;
    unsigned short sll_hatype;
    unsigned char sll_halen;
    unsigned char sll_addr[8];
};

char* 
get_my_ip();

int 
areq(
        struct sockaddr* ip_addr,
        socklen_t sockaddrlen,
        struct hwaddr* hw_addr
    );

void 
ping_source(
        char src[INET_ADDRSTRLEN], 
        char dest[INET_ADDRSTRLEN], 
        int pf, 
        int pid, 
        int * terminate, 
        pthread_mutex_t * race
        );

void print_status(
		char src_name[5]
		);

struct ip * prep_iphdr(
				int ipdata_size,
				char src_id[INET_ADDRSTRLEN],
				char dst_id[INET_ADDRSTRLEN],
				int protocol
				);

void *  prep_ipdata(
				char src_ip[INET_ADDRSTRLEN],
				int total_nodes,
				int next_node,
				char ** im_ip,
				char multicast_ip[INET_ADDRSTRLEN],
				int multicast_port
				);

void subscribe( 
				char mul_addr[INET_ADDRSTRLEN],
				int multicast_port,
				int udp_recvfd
			  );

void get_name(
			char name[5],
			char ip_addr[INET_ADDRSTRLEN]
			);

static void * start_ping(
						void * arg 
						);
void
send_unicast(
				int sockfd,
				char src_mac[],
				char dest_mac[],
				int ifindex,
				void * data_to_send,
				size_t len_data,
                int proto
		   );
			

# include "globals.h"

/**
 * Prepares the IP data for sending to other VM's
 */
void *  
prep_ipdata(
        char src_ip[INET_ADDRSTRLEN],
        int total_nodes,
        int next_node,
        char ** im_ip,
        char multicast_ip[INET_ADDRSTRLEN],
        int multicast_port
        )
{
    void * data = (void *) malloc(sizeof(ip_data) + total_nodes * INET_ADDRSTRLEN);
    ip_data * ipd = malloc(sizeof(ip_data));
    int i;	

    strcpy(ipd->src_ip, src_ip);
    ipd->total_nodes = total_nodes;
    ipd->next_node = next_node;
    strcpy(ipd->multicast_ip, multicast_ip);
    ipd->multicast_port = multicast_port;

    bzero(data, sizeof(ip_data) + total_nodes * INET_ADDRSTRLEN);

    memcpy(data, (void *) ipd, sizeof(ip_data));
    void * ptr = data + sizeof(ip_data);

    printf("\nNext node in the Tour ==>\n");

    for(i = 1; i <= total_nodes; i++ )
    {
        strncpy((char*) ptr, im_ip[i], INET_ADDRSTRLEN);

        if(ipd->next_node - 1 == i)
        {
            printf("==> [%s] \n",(char *) ptr);
        }	
        else
        {
            printf("    [%s] \n",(char *) ptr);
        }

        ptr += INET_ADDRSTRLEN;
    }

    return data;
}

/** 
  Gets the canonical IP address of the vm
 */
char*
get_my_ip()
{
    struct hwa_info	*hwa, *hwahead;

    char ETH0_NAME[5] = "eth0";
    struct sockaddr	*sa;

    char * ip_addr = (char*) malloc(INET_ADDRSTRLEN + 1);

    bzero(ip_addr, INET_ADDRSTRLEN + 1);

    for (hwahead = hwa = Get_hw_addrs(); hwa != NULL; hwa = hwa->hwa_next) 
    {
        if (strncmp(hwa->if_name, ETH0_NAME, 4) == 0)
        {
            if ( (sa = hwa->ip_addr) != NULL)
            {	
                strcpy(ip_addr, Sock_ntop_host(sa, sizeof(*sa)));
            }

            break;
        }
    }

    return ip_addr;
}

/** 
*  Gets the Hardware address of the vm
*/
char *
get_my_hw_addr()
{
    int i;
    int ix = 0;
    int jx;
    int err;

    struct hwa_info	*hwa, *hwahead;
    char   *ptr;

    char ETH0_NAME[5] = "eth0";
    struct sockaddr	*sa;

    char *my_hw_addr = (char*) malloc(6);

    for (hwahead = hwa = Get_hw_addrs(), ix = 0; hwa != NULL; hwa = hwa->hwa_next) 
    {
        //
        // Get all 'eth0' interfaces.
        //

        if (strncmp(hwa->if_name,ETH0_NAME, 4) == 0)
        {
            if ( (sa = hwa->ip_addr) == NULL)
            {	
                continue;
            }

            ptr = hwa->if_haddr;
            i = IF_HADDR;
            jx = 0;

            do {
                my_hw_addr[jx] = *ptr++;
                jx++;
            } while (--i > 0);

            break;
        }

        ix++;
    }
    
    return my_hw_addr;
}

/**
 * Prepares the IP header for sending to other VM's
 */
struct ip * 
prep_iphdr(
        int ipdata_size,
        char src_id[INET_ADDRSTRLEN],
        char dst_id[INET_ADDRSTRLEN],
        int protocol
        )
{
    struct ip * iph = (struct ip *) malloc(sizeof(struct ip));

    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_tos = 0;
    iph->ip_len = htons(sizeof(struct ip) + ipdata_size);
    iph->ip_id = htons(IPPROTO_ID);
    iph->ip_off = 0;
    iph->ip_ttl = htons(64);
    iph->ip_p = protocol;
    iph->ip_src.s_addr = inet_addr(src_id);
    iph->ip_dst.s_addr = inet_addr(dst_id);
    return iph;
}

char *  
process_recvd_rtpacket(
        int rt, 
        void * datagram, 
        char my_ip[INET_ADDRSTRLEN], 
        int  * ping_flag, 
        int  udp_sendfd, 
        int  udp_recvfd
        )
{
    struct ip * iph = (struct ip *) malloc(sizeof(struct ip));
    char str[INET_ADDRSTRLEN];
    char ping_node[INET_ADDRSTRLEN] = "";
    char my_name[5] = "\0";
    char src_name[5] = "\0";

    memcpy(iph, datagram, sizeof(struct ip));

    get_name(my_name, my_ip);

    if(iph->ip_id == htons(IPPROTO_ID))
    {
        //
        // Valid Packet
        //

        //
        // Route the packet to the next node on the list
        //

        void * ptr;
        ip_data * ipd = (ip_data *) malloc(sizeof(ip_data));
        char next_dest[INET_ADDRSTRLEN];
        struct sockaddr_in next_dst;
        int len;
        int i;

        datagram += sizeof(struct ip);
        memcpy(ipd, datagram, sizeof(ip_data));
        datagram += sizeof(ip_data);

        get_name(src_name, ipd->src_ip);
        print_status(src_name);

        if(* ping_flag != 1)
        {
            //
            // Node visited for the first time
            //

            strcpy(ping_node, ipd->src_ip);
            *ping_flag = 1;
            printf("Node visited for the first time\n");

            subscribe(ipd->multicast_ip, ipd->multicast_port, udp_recvfd);
        }

        ipd->next_node++;

        ptr = datagram;
        printf("\nNext node in the Tour ==>\n");
        for(i = 0; i < ipd->total_nodes; i++ )
        {
            if(ipd->next_node == i)
            {
                printf("==> %s \n",(char *)((int *)datagram));
                memcpy((void* ) next_dest, datagram, INET_ADDRSTRLEN);
            }	
            else
            {
                printf("    %s \n",(char *)((int *)datagram));
            }

            datagram += INET_ADDRSTRLEN;
        }

        if(ipd->next_node  == ipd->total_nodes)
        {
            //
            // Packet Reached Destination. Initiating Multicast
            //

            char buf[BUF_SIZE];
            int len;

            struct sockaddr_in sock_recv;

            printf("Packet reached destination node.\n");
            strcpy(buf,"\n<<<<< This is node ");
            strcat(buf, my_name);
            strcat(buf,". Tour has ended. Group members please identify yourselves  >>>>>\n");

            printf("\nNode %s. Sending %s", my_name, buf);

            bzero(&sock_recv, sizeof(sock_recv));
            sock_recv.sin_family = AF_INET;
            sock_recv.sin_port = htons(MULTICAST_PORT);
            Inet_pton(AF_INET, MULTICAST_ADDR, &sock_recv.sin_addr);

            if(sendto(udp_sendfd, buf, BUF_SIZE, 0, (SA *) &sock_recv, sizeof(sock_recv)) < 0)
            {
                perror("Send to error");
            }
        }
        else
        {
            len = sizeof(ip_data) + (ipd->total_nodes) * INET_ADDRSTRLEN;
            iph = (struct ip *) prep_iphdr(len, my_ip, next_dest, IPPROTO_RT);

            datagram = (void *) malloc(sizeof(struct ip) + len);

            memcpy(datagram, (void*) iph, sizeof(struct ip));
            memcpy(datagram + sizeof(struct ip), ipd, len);
            memcpy(datagram + sizeof(struct ip) + sizeof(ip_data), ptr, ipd->total_nodes * INET_ADDRSTRLEN);

            len += sizeof(struct ip);

            bzero(&next_dst, sizeof(next_dst));
            next_dst.sin_family = AF_INET;
            Inet_pton(AF_INET, next_dest, &next_dst.sin_addr);

            Sendto(rt, datagram, len , 0, (SA *) &next_dst, sizeof(next_dst));
        }
    }
    else
    {
        printf("\nInvlaid Packet Received ... Discarding it!!\n");
    }

    return ping_node;
}

/**
 * Creates a cache table entry
 */
cache_entry*
create_cache_entry(
        char ip_addr[],
        unsigned char hw_addr[],
        int sockfd
        )
{
    cache_entry* ce = (cache_entry*) malloc(sizeof(cache_entry));
    
    //
    // Set IP address.
    //
    Inet_pton(AF_INET, ip_addr, &ce->ce_ip_addr.s_addr);

    //
    // Set ethernet address.
    //

    memcpy(ce->ce_hw_addr, hw_addr, 6);

    ce->ce_ifindex = 2;
    ce->ce_incomplete = 1;
    ce->ce_sockfd = sockfd;
    return ce;
}

/**
 * Appends a cache table entry
 */
void
append_cache(
        cache_entry* ce,
        ar_cache* head
        )
{
    ar_cache* ne = (ar_cache*) malloc(sizeof(ar_cache));
    ar_cache* tmp;

    ne->ar_entry = ce;
    ne->ar_next = NULL;

    if (head->ar_next == NULL)
    {
        head->ar_next = ne;
        return;
    }

    tmp = head->ar_next;

    while (tmp->ar_next != NULL)
    {
        tmp = tmp->ar_next;
    }

    tmp->ar_next = ne;
}

cache_entry*
find_ip_addr_in_cache(
        char ip_addr[],
        ar_cache* head
        )
{
    ar_cache* cur = NULL;
    char ce_ip_addr[16];

    if (head->ar_next == NULL)
    {
        return NULL;
    }

    cur = head->ar_next;

    while (cur != NULL)
    {
        Inet_ntop(AF_INET, &cur->ar_entry->ce_ip_addr.s_addr, ce_ip_addr, 16);

        if (strcmp(ce_ip_addr, ip_addr) == 0)
        {
            return cur->ar_entry;
        }

        cur = cur->ar_next;
    }

    return NULL;
}

/**
 * Finds a cache table entry
 */
cache_entry*
find_cache_entry(
        char ip_addr[],
        unsigned char mac_addr[],
        ar_cache* head
        )
{
    ar_cache* cur = NULL;
    char ce_ip_addr[16];

    if (head->ar_next == NULL)
    {
        return NULL;
    }

    cur = head->ar_next;

    while (cur != NULL)
    {
        Inet_ntop(AF_INET, &cur->ar_entry->ce_ip_addr.s_addr, ce_ip_addr, 16);

        if (strcmp(ce_ip_addr, ip_addr) == 0 &&
                mac_cmp(cur->ar_entry->ce_hw_addr, mac_addr) == 0)
        {
            return cur->ar_entry;
        }

        cur = cur->ar_next;
    }

    return NULL;
}

/**
 * Deletes a cache table entry
 */
void 
delete_from_cache(
        int sockfd,
        ar_cache* head
        )
{
    ar_cache* cur = head->ar_next;
    ar_cache* prev = head;

    while (cur != NULL)
    {
        if (cur->ar_entry->ce_sockfd == sockfd)
        {
            prev->ar_next = cur->ar_next;
            
            free (cur);
            cur = NULL;

            trace;
            return;
        }

        prev = cur;
        cur = cur->ar_next;
    }
}

/**
 * Compares the MAC addresses
 */
int mac_cmp(
    unsigned char mac1[],
    unsigned char mac2[]
    )
{
    int i = 0;

    for (; i < 6; i++)
    {
        if ((mac1[i] & 0xff) != (mac2[i] & 0xff))
        {
            return 1;
        }
    }

    return 0;
}

/**
 * Prints the MAC addresses
 */
void 
print_mac_addr(
        unsigned char mac[]
        )
{
    int i;
    
    for (i = 0; i < 6; i++)
    {
        printf("%.2x%s", (mac[i] & 0xff), ":");
    }

    printf("\n");
}

/**
 * Prints the values stores in ARP cache
 */
void
print_arp_cache(
        ar_cache* head
        )
{
    ar_cache* cur;
    char ce_ip_addr[16];

    printf("ARP CACHE:\nIP || Sockfd || INCOMPLETE || MAC\n***\n");

    if (head->ar_next == NULL)
    {
        printf("Empty.\n***\n");
        return;
    }

    cur = head->ar_next;

    while (cur != NULL)
    {
        Inet_ntop(AF_INET, &cur->ar_entry->ce_ip_addr.s_addr, ce_ip_addr, 16);
    
        printf("%s || %d || %d || ", ce_ip_addr, cur->ar_entry->ce_sockfd,
                cur->ar_entry->ce_incomplete);

        print_mac_addr(cur->ar_entry->ce_hw_addr);

        cur = cur->ar_next;
    }

    printf("****\n");
}

/**
 * Prints the eth0 information
 */
void
print_eth0_info()
{
    int i;
    int ix = 0;
    int jx;
    int err;

    struct hwa_info	*hwa, *hwahead;
    char   *ptr;

    char ETH0_NAME[5] = "eth0";
    struct sockaddr	*sa;

    printf("Address Pairs:\n");

    for (hwahead = hwa = Get_hw_addrs(), ix = 0; hwa != NULL; hwa = hwa->hwa_next) 
    {
        //
        // Get all 'eth0' interfaces.
        //

        if (strncmp(hwa->if_name,ETH0_NAME, 4) == 0)
        {
            if ( (sa = hwa->ip_addr) == NULL)
            {	
                continue;
            }

            printf("<%s, ", Sock_ntop_host(sa, sizeof(*sa)));
            
            ptr = hwa->if_haddr;
            i = IF_HADDR;
            jx = 0;

            do {
                printf("%.2x%s", (*ptr++ & 0xff), (i == 1) ? " " : ":");
                jx++;
            } while (--i > 0);

            printf(">\n");
        }

        ix++;
    }
}

/**
 * Binds the socket descriptor to the eth0 interface
 */
void
bind_eth0(
        int sockfd
        )
{
    int i;
    int ix = 0;
    int jx;
    int err;

    struct hwa_info	*hwa, *hwahead;
    char   *ptr;

    char ETH0_NAME[5] = "eth0";
    struct sockaddr	*sa;

    struct sockaddr_ll socket_addr;

    for (hwahead = hwa = Get_hw_addrs(), ix = 0; hwa != NULL; hwa = hwa->hwa_next) 
    {
        //
        // Get all 'eth0' interfaces.
        //

        if (strncmp(hwa->if_name,ETH0_NAME, 4) == 0)
        {
            if ( (sa = hwa->ip_addr) == NULL)
            {	
                continue;
            }

            bzero(&socket_addr, sizeof(socket_addr));

            socket_addr.sll_family = AF_PACKET;
            socket_addr.sll_ifindex = hwa->if_index;
            socket_addr.sll_protocol = htons(IPPROTO_ID);
            socket_addr.sll_halen = ETH_ALEN;
            socket_addr.sll_addr[6] = 0x00;
            socket_addr.sll_addr[7] = 0x00;

            ptr = hwa->if_haddr;
            i = IF_HADDR;
            jx = 0;

            do {
                socket_addr.sll_addr[jx] = (*ptr++ & 0xff);
                jx++;
            } while (--i > 0);

            Bind(sockfd, (struct sockaddr *) &socket_addr, sizeof(socket_addr));
            trace;

            break;
        }

        ix++;
    }
}

/**
  Function to flood an interface.
*/
void
flood_interface(
        int sockfd,
        int ifindex,
        char mac_addr[],
        void * data_to_send,
        size_t len_data
        )
{
    int err;

    unsigned char dest_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    //
    // Buffer for the ethernet frame.
    //

    void* buffer = (void*)malloc(ETH_FRAME_LEN);

    struct sockaddr_ll * addr = (struct sockaddr_ll*) malloc(sizeof(struct sockaddr_ll));

    //
    // pointer to ethenet header
    // 

    unsigned char* etherhead = buffer;

    //
    // userdata in ethernet frame
    //

    unsigned char* data = buffer + 14;

    //
    // another pointer to ethernet header
    //

    struct ethhdr *eh = (struct ethhdr *)etherhead;

    bzero(addr, sizeof(addr));

    //
    // Prepare sockaddr_ll
    //

    addr->sll_family   = PF_PACKET;	
    addr->sll_protocol = htons(IPPROTO_ID);	
    addr->sll_ifindex  = ifindex;
    addr->sll_hatype   = ARPHRD_ETHER;
    addr->sll_pkttype  = PACKET_OTHERHOST;
    addr->sll_halen    = ETH_ALEN;		

    //
    // Set MAC for flooding. 
    //

    addr->sll_addr[0]  = 0xFF;		
    addr->sll_addr[1]  = 0xFF;		
    addr->sll_addr[2]  = 0xFF;
    addr->sll_addr[3]  = 0xFF;
    addr->sll_addr[4]  = 0xFF;
    addr->sll_addr[5]  = 0xFF;

    addr->sll_addr[6]  = 0x00;
    addr->sll_addr[7]  = 0x00;

    //
    // Set the frame header.
    //

    memcpy((void*)buffer, (void*)dest_mac, ETH_ALEN);
    memcpy((void*)(buffer+ETH_ALEN), (void*)mac_addr, ETH_ALEN);
    eh->h_proto = htons(IPPROTO_ID);

    memcpy(data, data_to_send, len_data);

    Sendto(sockfd, buffer, ETH_FRAME_LEN, 0, (struct sockaddr*) addr, sizeof(*addr));

    printf("Broadcast successful.\n");
}

/**
 * Gets the hardware address of the eth0 interface
 */
void 
get_eth0_hwinfo(
        unsigned char mac_addr[],
        int *ifindex
        )
{
    int i;
    int ix = 0;
    int jx;
    int err;

    struct hwa_info	*hwa, *hwahead;
    char   *ptr;

    char ETH0_NAME[5] = "eth0";
    struct sockaddr	*sa;

    for (hwahead = hwa = Get_hw_addrs(), ix = 0; hwa != NULL; hwa = hwa->hwa_next) 
    {
        //
        // Get all 'eth0' interfaces.
        //

        if (strncmp(hwa->if_name,ETH0_NAME, 4) == 0)
        {
            if ( (sa = hwa->ip_addr) == NULL)
            {	
                continue;
            }

            *ifindex = hwa->if_index;
            ptr = hwa->if_haddr;
            i = IF_HADDR;
            jx = 0;

            do {
                mac_addr[jx] = (*ptr++ & 0xff);
                jx++;
            } while (--i > 0);

            break;
        }

        ix++;
    }
}

/**
 * Prepares the arp packet header
 */
arp_header*
prep_arp_header(
        uint16_t op
        )
{
    arp_header* hdr = (arp_header*) malloc(sizeof(arp_header));

    hdr->ah_hard_type = htons(1);
    hdr->ah_prot_type = htons(0x800);

    hdr->ah_hard_size = 6;
    hdr->ah_prot_size = 4;

    hdr->ah_op = htons(op);

    hdr->ah_id = htons(ARP_ID);

    return hdr;
}

/**
 * Prepares the arp request packet header
 */
arp_header*
prep_arp_req_hdr(   
        struct in_addr * target_ip
        )
{
    arp_header* hdr = prep_arp_header(ARP_OP_ARP_REQ);
    int ifindex;

    //
    // Get my mac and set the value in the header.
    //

    get_eth0_hwinfo(hdr->ah_sender_eth_addr, &ifindex);

    //
    // Set my IP addr in the header.
    //
    
    Inet_pton(AF_INET, get_my_ip(), &hdr->ah_sender_ip_addr.s_addr);

    //
    // Set target ip addr.
    //

    memcpy(&hdr->ah_target_ip_addr, target_ip, sizeof(struct in_addr));

    //
    // Set taget mac to 0. Implies, it's uninitialized.
    //

    bzero(hdr->ah_target_eth_addr, 6);

    return hdr;
}

/**
 * Prepares the arp reply packet header
 */
arp_header*
prep_arp_rep_hdr(
        struct in_addr * target_ip,
        unsigned char target_hw_addr[]
        )
{
    arp_header* hdr = prep_arp_header(ARP_OP_ARP_REP);
    int ifindex;
    int ix;

    //
    // Get my mac and set the value in the header.
    //

    get_eth0_hwinfo(hdr->ah_sender_eth_addr, &ifindex);

    //
    // Set my IP addr in the header.
    //
    
    Inet_pton(AF_INET, get_my_ip(), &hdr->ah_sender_ip_addr.s_addr);

    //
    // Set target ip addr.
    //

    memcpy(&hdr->ah_target_ip_addr, target_ip, sizeof(struct in_addr));

    //
    // Set taget mac.
    //

    bzero(hdr->ah_target_eth_addr, 6);

    for (ix = 0; ix < 6; ix++)
    {
        hdr->ah_target_eth_addr[ix] = target_hw_addr[ix];
    }

    return hdr;
}

/**
 * Gets the name of the host
 */
void get_name(
        char name[5],
        char ip_addr[INET_ADDRSTRLEN]
        )
{
    struct hostent *hptr;			
    struct in_addr ipv4_addr;

    Inet_pton(AF_INET, ip_addr, &ipv4_addr.s_addr);

    if ( (hptr = gethostbyaddr(&ipv4_addr.s_addr, 4, AF_INET)) == NULL) 
    {
        err_msg("GET HOST BY ADDRESS ERROR :: %s: %s\n", ip_addr, hstrerror(h_errno));
        exit(1);
    }

    strcpy(name, hptr->h_name);
}

/**
 * Prints the timestamp
 */
void 
print_status(
        char src_name[5]
        )
{
    struct timeval t;
    time_t rawtime;
    struct tm * timeinfo;
    char curr_time[100]= "\0";
    int i;

    time ( &rawtime );
    timeinfo = localtime ( &rawtime );
    strcpy(curr_time, asctime(timeinfo));
    curr_time[strlen(curr_time) - 1] = '\0';

    printf("\n<%s> received source routing packet from <%s>\n", curr_time, src_name);
}

/**
 * Subscribes to the multicast group
 */
void 
subscribe( 
        char mul_addr[INET_ADDRSTRLEN],
        int multicast_port,
        int  udp_recvfd
        )
{
    struct sockaddr_in sock_recv;

    bzero(&sock_recv, sizeof(sock_recv));

    sock_recv.sin_family = AF_INET;
    sock_recv.sin_port = htons(multicast_port);
    Inet_pton(AF_INET, mul_addr, &sock_recv.sin_addr);

    Bind(udp_recvfd, (SA *) &sock_recv, sizeof(sock_recv));

    Mcast_join(udp_recvfd, (SA *) &sock_recv, sizeof(sock_recv), NULL, 0);

    printf("Joined the Multicast group :- Multicast IP%s Multicast Port %d\n", mul_addr, multicast_port);
}

/**
 * Send unicast to the destination specified in the argument
 */
void
send_unicast(
        int sockfd,
        char src_mac[],
        char dest_mac[],
        int ifindex,
        void * data_to_send,
        size_t len_data,
        int proto_num
        )
{
    int err;
    int ix;

    struct sockaddr_ll * addr = (struct sockaddr_ll*) malloc(sizeof(struct sockaddr_ll));

    //
    // Buffer for the ethernet frame.
    //

    void* buffer = (void*)malloc(ETH_FRAME_LEN);

    //
    // pointer to ethenet header
    // 

    unsigned char* etherhead = buffer;

    //
    // userdata in ethernet frame
    //

    unsigned char* data = buffer + 14;

    //
    // another pointer to ethernet header
    //

    struct ethhdr *eh = (struct ethhdr *)etherhead;

    bzero(addr, sizeof(addr));

    //
    // Prepare sockaddr_ll
    //

    addr->sll_family   = PF_PACKET;	
    addr->sll_protocol = htons(proto_num);	
    addr->sll_ifindex  = ifindex;
    addr->sll_hatype   = ARPHRD_ETHER;
    addr->sll_pkttype  = PACKET_OTHERHOST;
    addr->sll_halen    = ETH_ALEN;		

    //
    // Set MAC for flooding. 
    //

    for (ix  = 0; ix < 6; ix++)
    {
        addr->sll_addr[ix] = dest_mac[ix];
    }

    addr->sll_addr[6]  = 0x00;
    addr->sll_addr[7]  = 0x00;

    //
    // Set the frame header.
    //

    memcpy((void*)buffer, (void*)dest_mac, ETH_ALEN);
    memcpy((void*)(buffer+ETH_ALEN), (void*)src_mac, ETH_ALEN);
    eh->h_proto = htons(proto_num);

    memcpy((void *)data,(void *)data_to_send, len_data);

    Sendto(sockfd, buffer, ETH_FRAME_LEN, 0, (struct sockaddr*) addr, sizeof(*addr));
}

/**
 * Checks and updates the arp cache table
 */
void
check_and_update_arp_cache(
        char sender_ip_addr_buf[],
        unsigned char mac_addr_buf[],
        ar_cache* arp_cache 
        )
{
    cache_entry* found_ce = NULL;
    
    print_arp_cache(arp_cache);

    found_ce = find_cache_entry(sender_ip_addr_buf, mac_addr_buf, arp_cache);

    printf("Caching sender's IP addr.\n");

    if (found_ce == NULL)
    {
        //
        // Add to cache.
        //

        printf("No entry in cache.\n");

        append_cache(create_cache_entry(sender_ip_addr_buf, mac_addr_buf, -1), arp_cache);
    }
    else
    {
        //
        // Update the cache.
        //

        printf("Entry found in cache.\n");
    }

    print_arp_cache(arp_cache);
}

/**
 * Sets the hardware addresses
 */
void 
set_hwaddr(
        struct hwaddr* hw_addr,
        unsigned char eth_addr[]
        )
{
    hw_addr->sll_ifindex = 2;
    hw_addr->sll_hatype = 0;
    hw_addr->sll_halen = ETH_ALEN;

    memset(&hw_addr->sll_addr, 0, 8);
    memcpy(&hw_addr->sll_addr, eth_addr, 6);
}

/**
  Prints the contents of a ARP packet.
  */
void 
print_arp_packet(
    arp_header* pkt
    )
{
    char ip_buf[16];

    printf("ARP Packet:\n***\n");

    printf("Hard Type: %d\tProt Type: %d\tHard Size: %d\tProt Size: %d\n",
            ntohs(pkt->ah_hard_type), ntohs(pkt->ah_prot_type), pkt->ah_hard_size,
            pkt->ah_prot_size);

    printf("Op: %d\t Id: %d\n", ntohs(pkt->ah_op), ntohs(pkt->ah_id));

    Inet_ntop(AF_INET, &pkt->ah_sender_ip_addr.s_addr, ip_buf, 16);

    printf("Sender IP address: %s ", ip_buf);

    Inet_ntop(AF_INET, &pkt->ah_target_ip_addr.s_addr, ip_buf, 16);
    
    printf("Destination IP address: %s\n", ip_buf);

    printf("Sender eth Addr:\n");

    print_mac_addr(pkt->ah_sender_eth_addr);

    printf("Destination eth Addr:\n");

    print_mac_addr(pkt->ah_target_eth_addr);

    printf("***\n");
}




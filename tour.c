# include "globals.h"

//
// Mutex variable for terminate
//

pthread_mutex_t race = PTHREAD_MUTEX_INITIALIZER;

//
// If terminate is set, the Thread pinging the source node of the Tour Exits
//

int terminate = 0;

int sig_flag = AREQ_FLAG;

int stream_sockfd;
static void sig_alrm(int signo);
static sigjmp_buf jmpbuf;

int main(int argc, char ** argv)
{
    int rt;
    int pg;
    int pf_sockfd;
    int udp_sendfd;
    int udp_recvfd;
    const int on = 1;
    int i;
    int j;
    int err;
    int maxfd;
    int len;
    int ping_flag = 0;

    char my_name[5] = "\0";
    char str[INET_ADDRSTRLEN];
    char src_ip[INET_ADDRSTRLEN];
    char ping_node[INET_ADDRSTRLEN];
    char **pptr;

    socklen_t salen = 0;
    struct sockaddr * sasend, * sarecv;
    struct sockaddr_in sock_send, sock_recv;
    struct hostent *hptr;

    struct sockaddr_in rtaddr;

    void  * ipd;
    struct ip * iph;

    void * datagram;
    void * buffer;
    fd_set rset;

    pthread_t tid;

    sasend = (SA *) malloc(sizeof(SA));
    sarecv = (SA *) malloc(sizeof(SA));

    strcpy(src_ip, get_my_ip());
    get_name(my_name, src_ip);

    rt = socket(AF_INET, SOCK_RAW, IPPROTO_RT);

    bzero(&rtaddr, sizeof(rtaddr));
    rtaddr.sin_family = AF_INET;
    Inet_pton(AF_INET, src_ip, &rtaddr.sin_addr);

    Bind(rt, (SA *) &rtaddr, sizeof(rtaddr));

    if(setsockopt(rt, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
    {
        perror("\n Setsockopt error :");
    }

    pg = Socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    pf_sockfd = Socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));

    Signal(SIGALRM, sig_alrm);

    udp_sendfd = Socket(AF_INET, SOCK_DGRAM, 0);
    udp_recvfd = Socket(AF_INET, SOCK_DGRAM, 0);

    if (argc > 1)
    {
        //
        // This is the Source node. It creates and joins a Multicast group. Multicast address and Portno specified in globals.h
        //
        char mul_addr[INET_ADDRSTRLEN];
        char ** im_ip = (char **) malloc((argc + 1) * sizeof(char*));

        struct sockaddr_in next_dst;

        printf("\nNode %s is the Source of the Tour. Starting Tour\n", my_name);
		
		strcpy(mul_addr, MULTICAST_ADDR);

        bzero(&sock_recv, sizeof(sock_recv));
        sock_recv.sin_family = AF_INET;
        sock_recv.sin_port = htons(MULTICAST_PORT);
        Inet_pton(AF_INET, mul_addr, &sock_recv.sin_addr);

        Bind(udp_recvfd, (SA *) &sock_recv, sizeof(sock_recv));

        Mcast_join(udp_recvfd, (SA *) &sock_recv, sizeof(sock_recv), NULL, 0);

        //
        // Get the Address of all the vms
        //

        for(i = 1; i < argc; i++)	
        {
            im_ip[i] = (char *) malloc(INET_ADDRSTRLEN);
            if ( (hptr = gethostbyname(argv[i])) == NULL) //Checks validity of Domain name
            {
                err_msg("GET HOST BY NAME ERROR :: %s: %s\n", argv[i], hstrerror(h_errno));
                exit(1);
            }								
            switch (hptr->h_addrtype) 
            {
                case AF_INET:
                    pptr = hptr->h_addr_list;
                    Inet_ntop(hptr->h_addrtype, *pptr, str, sizeof(str));
                    strcpy(im_ip[i], str);

                    if (strcmp(argv[i], my_name) == 0)
                    {
                        printf("Tour cannot contain source node.\n");
                        exit(1);
                    }

                    printf("\nIPV4 Address %s : %s\n", argv[i], im_ip[i]);

                    break;
                default:
                    err_ret("unknown address type\n");
                    break;
            }

        }

        ipd = prep_ipdata(src_ip, argc-1, 0, im_ip, mul_addr, MULTICAST_PORT);
        len = sizeof(ip_data) + (argc - 1) * INET_ADDRSTRLEN;

        iph = (struct ip *) prep_iphdr(len, src_ip, im_ip[1], IPPROTO_RT);

        datagram = (void *) malloc(sizeof(struct ip) + len);

        memcpy(datagram, (void*) iph, sizeof(struct ip));
        memcpy(datagram + sizeof(struct ip), ipd, len);

        len += sizeof(struct ip);

        bzero(&next_dst, sizeof(next_dst));
        next_dst.sin_family = AF_INET;
        Inet_pton(AF_INET, im_ip[1], &next_dst.sin_addr);

        Sendto(rt, datagram, len , 0, (SA *) &next_dst, sizeof(next_dst));

    }
	else
	{
		printf("\n Node %s is not the Tour Source. Waiting for Tour Commencement\n", my_name);
	}
    while(1)
    {

        FD_ZERO(&rset);
        FD_SET(rt, &rset);
        FD_SET(pg, &rset);
        FD_SET(udp_recvfd, &rset);

        maxfd = max(rt, pg);
        maxfd = max(maxfd, udp_recvfd);

        err = select(maxfd + 1, &rset, NULL, NULL, NULL);

        if (err < 0 && errno == EINTR)
        {
            printf("EINTR error");
            continue;
        }
        else if (err < 0)
        {
            perror("Select Error");
            exit(1);
        }


        if(FD_ISSET(rt, &rset))
        {

			//
			// Tour Packet Received 
			//
			
            datagram = (void *) malloc(IP_MAXPACKET);
            Recvfrom(rt, datagram, IP_MAXPACKET, 0,  NULL, NULL);

            usleep(400000);
            strcpy(ping_node, process_recvd_rtpacket(rt, datagram, src_ip, &ping_flag, udp_sendfd, udp_recvfd));

            if(strcmp(ping_node, "") != 0)
            {
                struct src_dest_info sd;

                strcpy(sd.src, src_ip);
                strcpy(sd.dest, ping_node);
                sd.pf = pf_sockfd;
                sd.pid = getpid();

                printf("\nPinging the source node of the Tour %s\n", sd.dest);

				//
				// Create a new Thread which works concurrently with the main Thread. This new thread pings the Source of the Tour every second.
				//

                Pthread_create(&tid, NULL, &start_ping, (void *) &sd);
            }
        }

        if(FD_ISSET(udp_recvfd, &rset))
        {

			//
			// Multicast Message Received
			//
			
            char buf[BUF_SIZE];

            Recvfrom(udp_recvfd, buf, BUF_SIZE, 0, NULL, NULL);

            printf("\nNode %s. Received %s", my_name, buf);

            if(strstr(buf, "Tour has ended") != NULL)
            {
				//
				// End of Tour. Pinging to Source will be stopped. A alarm of 5 seconds will be set after which Tour application exits
				//
			

                printf("\nPinging to the source node stopped\n");

                Pthread_mutex_lock(&race);
                terminate = 1;
                Pthread_mutex_unlock(&race);
				
                strcpy(buf,"\n<<<<< Node ");
                strcat(buf, my_name);
                strcat(buf,". I am a member of the group. >>>>>\n");
                printf("\nNode %s. Sending %s", my_name, buf);

                bzero(&sock_recv, sizeof(sock_recv));
                sock_recv.sin_family = AF_INET;
                sock_recv.sin_port = htons(MULTICAST_PORT);
                Inet_pton(AF_INET, MULTICAST_ADDR, &sock_recv.sin_addr);

                if(sendto(udp_sendfd, buf, BUF_SIZE, 0, (SA *) &sock_recv, sizeof(sock_recv)) < 0)
                {
                    perror("Send to error");
                }
			
				sig_flag = TOUR_FLAG;
				alarm(5);
				
            }
        }

        if(FD_ISSET(pg, &rset))
        {
			
			//
			// ICMP Ping packet Received
			//
		
            int bytes;
            struct sockaddr_in sarecv;
            socklen_t len;
            struct ip * iph;
            struct icmp * icmph;
            char str1[INET_ADDRSTRLEN];
            char str2[INET_ADDRSTRLEN];

            void * buffer = (void *) malloc(ETH_FRAME_LEN);

            iph = (struct ip *) malloc(sizeof(struct ip));

            icmph = (struct icmp *) malloc(8 + 56);

            len = sizeof(sarecv);

            if((bytes = recvfrom(pg, buffer, ETH_FRAME_LEN, 0, (SA *) &sarecv, &len)) < 0)
            {
                perror("Recv from error");
            }

            memcpy(iph, buffer, sizeof(struct ip));

            memcpy(icmph, buffer + sizeof(struct ip), 8 + 56);

            if(icmph->icmp_type == ICMP_ECHOREPLY)
            {
                struct timeval * ts = (struct timeval *) malloc(sizeof(struct timeval));
                struct timeval * tr = (struct timeval *) malloc(sizeof(struct timeval));
                double rtt;

                if(icmph->icmp_id != getpid())
                {
					//
					//	Packet doesn't belong to the Current Process
					//
					
                    continue;;
                }

                ts = (struct timeval *) icmph->icmp_data;
                Gettimeofday(tr, NULL);
                tv_sub(tr, ts);
                rtt = tr->tv_sec * 1000.0 + tr->tv_usec / 1000.0;
                printf("\n%d bytes from %s: seq=%u, ttl=%d, rtt=%.3f ms\n", (bytes - 20), str1, icmph->icmp_seq, iph->ip_ttl, rtt);
            }
        }
    }

    return 0;
}

//
// start_ping is the function called by the newly created Thread. This function initially detaches the thread and calls the ping_source funtion
//

static void * 
start_ping(
        void * arg
        )
{
    Pthread_detach(pthread_self());

    struct src_dest_info * sd = (struct src_dest_info *) malloc(sizeof(struct src_dest_info));

    memcpy((void *)sd, arg, sizeof(struct src_dest_info));

    ping_source(sd->src, sd->dest, sd->pf, sd->pid, &terminate, &race);

    return NULL;
}

int 
areq(
        struct sockaddr* ip_addr,
        socklen_t sockaddrlen,
        struct hwaddr* hw_addr
    )
{
    struct sockaddr_un servaddr;
    struct sockaddr_un cliaddr;
    fd_set rset;
    int clilen = sizeof(struct sockaddr_un);
    int err;

    stream_sockfd = Socket(AF_LOCAL, SOCK_STREAM, 0);

    bzero(&servaddr, sizeof(struct sockaddr_un));
    servaddr.sun_family = AF_LOCAL;
    strcpy(servaddr.sun_path, SERVER_PATH); 

    err = connect(stream_sockfd, (SA*) &servaddr, sizeof(struct sockaddr_un));
	
	if (err < 0)
	{
		 printf("Connection Error : Could not connect to ARP Module\n");
         return -1;
	}
    
    Write(stream_sockfd, ip_addr, sockaddrlen);
    
    alarm(2);

    while (1)
    {
        if (sigsetjmp (jmpbuf, 1) != 0)
        {
            //
            //
            //

            printf("Timeout waiting for ARP reply.\n");

            Close(stream_sockfd);
            return -1;
        }

        FD_ZERO (&rset);
        FD_SET (stream_sockfd, &rset);

        err = select(stream_sockfd + 1, &rset, NULL, NULL, NULL);

        if (err < 0 && errno == EINTR)
        {
            trace;
            printf("EINTR in select.\n");
        }

        if (FD_ISSET(stream_sockfd, &rset))
        {
            Read(stream_sockfd, hw_addr, sizeof(struct hwaddr));
            
            printf("AREQ returned with: ifindex: %d\tha type: %d\tha len: %d.\n", 
                    hw_addr->sll_ifindex, hw_addr->sll_hatype, hw_addr->sll_halen);
            
            printf("ETHERNET_ADDR:\n");

            print_mac_addr(hw_addr->sll_addr);

            alarm(0);
            return 0;
        }
    }

    return 0;
}

static void
sig_alrm(int signo)
{
	if(sig_flag == AREQ_FLAG)
	{
        printf("Timeout while waiting for AREQ reply.\n");
		sig_flag = TOUR_FLAG;
    	siglongjmp(jmpbuf, 1);
	}
	else
	{
		printf("\nExiting Tour Application\n");
		exit(0);
	}
}

//
//	ping_source prepares a ICMP ECHO Request packet and pings the Source node every second. It also acquires a lock on the mutex variable race to check
//  the value of the varibale terminate. if terminate is set this function returns.
//

void 
ping_source(
        char src[INET_ADDRSTRLEN], 
        char dest[INET_ADDRSTRLEN], 
        int pf, 
        int pid, 
        int * terminate, 
        pthread_mutex_t * race
        )
{

    struct ip * iph;
    struct icmp * icmph = (struct icmp *) malloc(8 + 56);

    int seq_no = 0;
    int len;
    int err;

    unsigned char src_mac[6];;
    unsigned char dest_mac[6];
    int ifiindex;

    int datalen = 56;

    void * datagram;
    struct hwaddr* hw_addr = (struct hwaddr*) malloc (sizeof(struct hwaddr));
    struct sockaddr_in dest_addr;

    char name[5] = "\0";
    get_name(name, dest);

    printf("\nPING %s (%s): %d data bytes\n", name, dest, datalen);

    Inet_pton(AF_INET, dest, &dest_addr.sin_addr.s_addr);

    printf("AREQ for %s.\n", dest);
    err = areq(&dest_addr, sizeof(struct sockaddr_in), hw_addr);

    if (err < 0)
    {
        printf("AREQ returned an error.\n");
        return;
    }

    memcpy(dest_mac, hw_addr->sll_addr, 6);

    get_eth0_hwinfo(src_mac, &ifiindex);
    iph = (struct ip *) prep_iphdr(8 + datalen, src, dest, IPPROTO_ICMP);

    iph->ip_sum = 0;	
    iph->ip_sum = in_cksum((u_short *)iph, sizeof(struct ip));

    icmph->icmp_type = ICMP_ECHO;
    icmph->icmp_code = 0;
    icmph->icmp_cksum = 0;
    icmph->icmp_seq = seq_no;
    icmph->icmp_id = pid;
    memset(&icmph->icmp_data, 0xa5, datalen);
    icmph->icmp_cksum = in_cksum((u_short *)icmph, 8 + datalen);

    //Signal(Src,GKILL, kill_my_thread);

    while(1)
    {
        memset(&icmph->icmp_data, 0xa5, datalen);
        Gettimeofday((struct timeval *)icmph->icmp_data, NULL);
        icmph->icmp_cksum = 0;
        icmph->icmp_seq = seq_no++;
        icmph->icmp_cksum = in_cksum((u_short *)icmph, 8 + datalen);

        len = sizeof(struct ip) + 8 + 56;

        datagram = (void *) malloc(len);

        memcpy(datagram, (void*) iph, sizeof(struct ip));
        memcpy(datagram + sizeof(struct ip), icmph, 8);
        memcpy(datagram + len - 56, icmph->icmp_data, 56);

        send_unicast(pf, src_mac, dest_mac, ifiindex, datagram, len, ETH_P_IP);

        sleep(1);
        Pthread_mutex_lock(race);
        if(*terminate == 1)
        {
            Pthread_mutex_unlock(race);
            return;
        }

        Pthread_mutex_unlock(race);
    }
}



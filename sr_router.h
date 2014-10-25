/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 * 90904102 
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#ifdef VNL
#include "vnlconn.h"
#endif

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024
/****************code added by mukunda************/
#define PACKET_SIZE 1024 
#define IP_QUEUE_SIZE 100
#define ARP_QUEUE_SIZE 100
/************************************************/

/* forward declare */
struct sr_if;
struct sr_rt;
/*************code added by mukunda*********/
struct arp_cache;
struct ip_queue;
/************************/
/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int  sockfd;   /* socket to server */
#ifdef VNL
    struct VnlConn* vc;
#endif
    char user[32]; /* user name */
    char host[32]; /* host name */
    char template[30]; /* template name if any */
    char auth_key_fn[64]; /* auth key filename */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
/*********code added by Mukunda-begin*******************/
    struct arp_cache* ac;
    struct queue* iq;
    struct queue* arp_req_queue;
/*********code added by Mukunda-end*******************/
    FILE* logfile;
};

/*********code added by Mukunda-begin*******************/
struct arp_cache
{
   uint32_t ip_addr;
   unsigned char mac_addr[6];
   uint8_t time_sec;
   struct arp_cache* next;
};

struct queue
{
   int capacity;
   int size;
   int front;
   int rear;
   uint32_t* elements;
};

/*********code added by Mukunda-end*******************/
    
/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance* );
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );
/***********code added by mukunda*************/
void form_arp_reply_packet(const struct sr_ethernet_hdr* , const struct sr_arphdr* , uint8_t*, char*,struct sr_instance* sr); 
void update_arp_table(struct sr_instance*,uint8_t*);
void catch_alarm(int sig); 
void update_arp_cache_timer(struct sr_instance* );
void check_arp_node(struct arp_cache**);
uint16_t find_checksum(uint16_t *);
void process_ip_packet(struct sr_instance*);
struct queue* create_queue(int);
uint8_t* get_q_front(struct queue* );
void enqueue(struct queue*, uint8_t*);
void check_arp_req_queue(struct sr_instance*);
struct sr_rt* get_rt_entry_from_rtable(long, struct sr_rt*);
char* get_dst_mac_from_arp_cache(long, struct arp_cache*);
uint8_t* form_arp_req_pkt(uint32_t,char*, struct sr_instance*);
uint16_t find_icmp_checksum(uint16_t*, int);
/*********************************************/

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );

#endif /* SR_ROUTER_H */

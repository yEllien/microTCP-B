#include "microtcp.h"


typedef enum
{
  ACK_F = 12,
  RST_F = 13,
  SYN_F = 14,
  FIN_F = 15
} microtcp_flag_bits_t;

typedef enum
{
    DUPLICATE,
    REGULAR
} microtcp_ack_type_t;




/* Sets given control bit in header to 1 */

static uint16_t set_bit (uint16_t data, uint16_t pos);




/* Returns 0 if bit not set, else !=0 */

static uint16_t get_bit (uint16_t data, uint16_t pos);




/* Creates a header according to the arguments */

static microtcp_header_t make_header (uint32_t seq_number,uint32_t ack_number, 
                                 uint16_t window, uint32_t data_len,
                                 uint8_t ACK, uint8_t RST, uint8_t SYN, uint8_t FIN);




/* Returns the header in the argument in host byte order */

static microtcp_header_t get_hbo_header (microtcp_header_t *nbo_header);




/* Returns 1 if header control is valid according to the given values, 0 otherwise */

static int is_header_control_valid (microtcp_header_t *hbo_header, uint8_t ACK, uint8_t RST, uint8_t SYN, uint8_t FIN);




/* Returns 1 if given header is of a FINACK */

int is_finack(void* header);




/* Returns 1 if the given addresses are equal */

static int is_equal_addresses (const struct sockaddr a, const struct sockaddr b);




/* Returns 1 if checksum is valid, 0 otherwise */

static int is_checksum_valid(const uint8_t *recv_buf, const size_t msg_len);




/* Returns 1 if given packet is corrupt */

int corrupt_packet(void *buffer);




/* checks that packet in buffer has the expected sequence number (is a continuous packet) */
/*  WE ASUME THAT BUFFER CONTAINS ONE PACKET */

int is_valid_seq(microtcp_sock_t *socket, void *buffer, size_t bytes_received);




/* Check that all the bytes of the packet have been received */

int received_all_bytes(microtcp_sock_t *socket, void *buffer, ssize_t received);




/* TODO: */

void update_window_size(microtcp_sock_t *socket);




/* Decide and send an appropriate ACK */

void send_ack(microtcp_sock_t *socket, void *buffer, ssize_t bytes_received);




/* Send given type of ACK */

void send_ack_type(microtcp_sock_t *socket, void *buffer, microtcp_ack_type_t flag);




/* update socket fields - keep track of transmitted packets */

void recv_update_socket_fields(microtcp_sock_t *socket, const void* buffer, const ssize_t bytes_received);








/* TODO: do we need this?
//returns the current window
uint16_t get_unacked (microtcp_socket_t *sock);

//returns the current window
uint16_t get_my_rwnd (microtcp_socket_t *sock);
*/


/* TODO: do we need this?*/
/* check if received packet has data or is just an ack */
/* 
int is_ack_seq(microtcp_sock_t *socket, void *buffer);
*/


//TODO: do we need this?
/*
struct SeqList{
  uint32_t seq_num;
  uint32_t data_len;
  struct SeqList *first;
  struct SeqList *last;
  struct SeqList *next;
}*seq_list;
*/
#include "helper.h"
#include <string.h>




static uint16_t set_bit (uint16_t data, uint16_t pos)
{
  return (data|(1 << pos));
}




static uint16_t get_bit (uint16_t data, uint16_t pos)
{
  return ((data >> pos) & 1);
}




static microtcp_header_t make_header (uint32_t seq_number,uint32_t ack_number, 
                                      uint16_t window, uint32_t data_len,
                                      uint8_t ACK, uint8_t RST, uint8_t SYN, uint8_t FIN)
{
  microtcp_header_t header;

  header.seq_number = htonl(seq_number);
  header.ack_number = htonl(ack_number);
  header.window = htons(window);
  header.data_len = htonl(data_len);
  header.future_use0 = 0;
  header.future_use1 = 0;
  header.future_use2 = 0;
  header.checksum = 0;
  uint16_t tmp_control = 0;
  if(ACK) set_bit(tmp_control, ACK_F);
  if(RST) set_bit(tmp_control, RST_F);
  if(SYN) set_bit(tmp_control, SYN_F);
  if(FIN) set_bit(tmp_control, FIN_F);
  header.control = htons(tmp_control);
  header.checksum = htonl(crc32((uint8_t *)(&header), sizeof(header)));

  return header;
}



void make_header_auto (microtcp_sock_t *socket, uint8_t *header, uint32_t seq_no)
{
	microtcp_header_t tmp_header;

	tmp_header = make_header(seq_no, socket->ack_number, 
													 socket->curr_win_size, data_len, 0, 0, 0, 0);

	memcpy(header, &tmp_header, sizeof(microtcp_header_t));
}




static microtcp_header_t get_hbo_header (uint8_t *nbo_packet)
{
  microtcp_header_t hbo_header, *nbo_header = (microtcp_header_t *) nbo_packet; 
  
  hbo_header.seq_number = ntohl(nbo_header->seq_number);
  hbo_header.ack_number = ntohl(nbo_header->ack_number);
  hbo_header.control = ntohs(nbo_header->control);
  hbo_header.window = ntohs(nbo_header->window);
  hbo_header.data_len = ntohl(nbo_header->data_len);
  hbo_header.future_use0 = ntohl(nbo_header->future_use0);
  hbo_header.future_use1 = ntohl(nbo_header->future_use1);
  hbo_header.future_use2 = ntohl(nbo_header->future_use2);
  hbo_header.checksum = ntohl(nbo_header->checksum);

  return hbo_header;
}




static int is_header_control_valid (microtcp_header_t *hbo_header, uint8_t ACK, 
																	  uint8_t RST, uint8_t SYN, uint8_t FIN)
{
  if(ACK && get_bit(hbo_header->control, ACK_F) == 0)
    return 0;
  if(RST && get_bit(hbo_header->control, RST_F) == 0)
    return 0;
  if(SYN && get_bit(hbo_header->control, SYN_F) == 0)
    return 0;
  if(FIN && get_bit(hbo_header->control, FIN_F) == 0)
    return 0;

  return 1;
}




int is_finack(void* buffer)
{
  return is_header_control_valid(get_hbo_header(buffer), 1, 0, 0, 1);
}




static int is_equal_addresses (const struct sockaddr a, const struct sockaddr b)
{
  if (a.sa_family != b.sa_family)
    return 0;
  if (strcmp(a.sa_data, b.sa_data) != 0)
    return 0;
  else return 1;
}




static int is_checksum_valid(const uint8_t *recv_buf, const size_t msg_len)
{

  microtcp_header_t *tmp_header;
  uint32_t received_checksum, calculated_checksum;
  int i = 0, size = 0;

  tmp_header = malloc(msg_len);
  
  memcpy(tmp_header, recv_buf, size);

  /* check sum in received header */
  received_checksum = ntohl(tmp_header->checksum);

  /* calculate checksum of header for comparison */
  calculated_checksum = ntohl(crc32(recv_buf, msg_len));

  return (received_checksum == calculated_checksum);
}




int corrupt_packet(void *buffer)
{
  return !is_checksum_valid(buffer);
}




int received_all_bytes(microtcp_sock_t *socket, void *buffer, ssize_t received)
{
  microtcp_header_t packet;
  uint32_t data_len;
  uint64_t header_length; 

  packet = get_hbo_header(buffer);

  data_len = packet.data_len;
  header_length = sizeof(microtcp_header_t);
  //TODO: how to add header_length + data_len

  return received == data_len + header_length;
}




int is_valid_seq(microtcp_sock_t *socket, void *buffer, size_t bytes_received)
{
  microtcp_header_t packet;
  uint32_t seq, data_len;

  /* check that it's not an ACK */
  if(!is_header_control_valid((microtcp_header_t *)buffer, 0, 0, 0, 0)) return 0;

  /* find sequence number field */
  packet = get_hbo_header(buffer);
  seq = packet.seq_number;

  /* new seq should be equal to the last ack sent */
  return seq == socket->ack_number;
}




void send_ack(microtcp_sock_t *socket, void *buffer, ssize_t bytes_received)
{

	/* if packet is corrupted send duplicate ack */
	if (corrupt_packet(buffer))
	{
		send_ack_type(socket, buffer, DUPLICATE);
		return -1;
	}

  if (is_finack(buffer))
  {
    socket->state = CLOSING_BY_PEER;
    microtcp_shutdown(socket, SHUT_RDWR);
    return -1;
  }

  /* received packet with data */
  if (!is_valid_seq(socket, buffer, length) || !received_all_bytes(socket, buffer, bytes_received))
	{
  	send_ack_type(socket, buffer, DUPLICATE);
		return -1;
  } 

  send_ack_type(socket, buffer, REGULAR);
	//TODO: ?? send data to application layer
  recv_update_socket_fields(socket, buffer, bytes_received);
	
	//TODO: flow control
	return bytes_received;
}




void send_ack_type(microtcp_sock_t *socket, void *buffer, microtcp_ack_type_t flag)
{
  microtcp_header_t packet, ack;
  uint32_t;

  if (flag == REGULAR)
	{
    
		/* not sending a duplicate ack so we have to extract seq_num and 
		   data_length from header to calculate the new ack num we want to send */

    packet = get_hbo_header(buffer);
    socket->ack_number = packet.seq_number + packet.data_len;  //TODO: check this . Checked, its OK
  } 

  /* if sending a dupACK, we just resend prev ack num in socket->ack_number */
  ack = make_header(socket->seq_number, socket->ack_number, socket->curr_win_size, 0, 1, 0, 0, 0);
  sendto(socket->sd, &ack, sizeof(ack), 0, socket->address, socket->address_len);
  // check stuff
} 






void recv_update_socket_fields(microtcp_sock_t *socket, const void* buffer, 
															 const ssize_t bytes_received)
{
  microtcp_header_t packet = get_hbo_header(buffer);
  uint32_t payload = packet.data_len;
  socket->packets_received++;
  socket->bytes_received += payload;
  socket->buf_fill_level += bytes_received;
  //update window
}



/* Stuff i dont know if we need or to be added  

void update_window_size(microtcp_sock_t *socket){

}
struct SeqList{
  uint32_t seq_num;
  uint32_t data_len;
  struct SeqList *first;
  struct SeqList *last;
  struct SeqList *next;
}*seq_list;


uint16_t get_unacked (microtcp_socket_t *sock)
{
  // unacked bytes = last byte sent - last byte acked
  return  sock->seq_number - sock->ack_number;
}

uint16_t get_my_rwnd (microtcp_socket_t *sock)
{
  // unread bytes = last byte received - last byte read
  //return MICROTCP_WIN_SIZE - (?? - sock->bytes_received)
}



int is_ack_seq(microtcp_sock_t *socket, void *buffer){
  microtcp_header_t packet = get_hbo_header(buffer);

  // is ACK 
  if(is_header_control_valid(buffer, 1, 0, 0, 0)) return 1;
  // it's a packet with data
  if(is_header_control_valid(buffer, 0, 0, 0, 0)) return 2;

}
*/
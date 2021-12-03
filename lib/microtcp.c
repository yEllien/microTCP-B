/*
 * microtcp, a lightweight implementation of TCP for teaching,
 * and academic purposes.
 *
 * Copyright (C) 2015-2017  Manolis Surligas <surligas@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "microtcp.h"
#include "../utils/crc32.h"
#include <stdio.h>
#include <stdlib.h>

microtcp_sock_t
microtcp_socket (int domain, int type, int protocol)
{
  microtcp_socket_t s;
  if ((s.sd = socket(domain, SOCK_DGRAM, IPPROTO_UDP)) == -1){
    perror("opening socket");
    exit(0);
  }
  s.state = UNKNOWN;
  return s;
}

int
microtcp_bind (microtcp_sock_t *socket, const struct sockaddr *address,
               socklen_t address_len)
{ int rv;
  if((rv = bind(socket->sd, address, address_len)) == -1){
    perror("TCP bind");
  }
  
  return rv;
}

static uint16_t set_bit (uint16_t data, uint16_t pos)
{
  return (data|(1 << pos));
}

//returns 0 if bit not set, else !=0
static uint16_t get_bit (uint16_t data, uint16_t pos)
{
  return ((data >> pos) & 1);
}

int
microtcp_connect (microtcp_sock_t *socket, const struct sockaddr *address,
                  socklen_t address_len)
{
  microtcp_header_t syn, *recv_header;
  struct sockaddr src_addr, src_addr_length;
  
  ssize_t bytes_sent, syn_length = sizeof(syn);
  srand(time(NULL));

  socket->seq_number = rand();  // create random sequence number for client
  syn.seq_number = socket->seq_number;
  syn.control = 0;
  syn.control = set_bit(syn.control, 14); // set SYN bit to 1

  bytes_sent = sendto(socket->sd, &syn, syn_length, address, address_len);
  socket->state = SYN_SENT;

  if(bytes_sent != syn_length){
    socket->state = INVALID;
    perror("server didn't receive all bytes");
    return socket->sd;
  } 
  
  do{
    recvfrom(socket->sd, socket->recvbuf, MICROTCP_RECVBUF_LEN, MSG_WAITALL, &src_addr, &src_addr_length);
    recv_header = socket->recvbuf;
  }while(*address != src_addr);
  
  // received synack from server

  // check that SYN and ACK bits are set to 1
  // check if ACK_received = SYN_sent + 1
  if( (get_bit(recv_header->control, 12) != 0) && (get_bit(recv_header->control, 14) != 0) && (recv_header->ack_number == socket->seq_number + 1) ){
    socket->server_addr = address;
    socket->server_addr_len = address_len;

    socket->state = ESTABLISHED;
  }else{
    socket->state = INVALID;
  }

  return socket->sd;
}


int
microtcp_accept (microtcp_sock_t *socket, struct sockaddr *address,
                 socklen_t address_len)
{
  socket->recvbuf = malloc(MICROTCP_RECVBUF_LEN * sizeof(char));
  socket->buf_fill_level = 0;
  
  microtcp_header_t *header;
  struct sockaddr src_addr;
  struct socklen_t src_addr_length;

  do
  {
    socket->buf_fill_level = receivefrom(socket->sd, &(socket->recvbuf), MICROTCP_RECVBUF_LEN, MSG_WAITALL, &src_addr, &src_addr_length);
    header = socket->recvbuf;
  } while (get_bit(header->control, 14) == 0);
  
  srand(time(NULL));
  socket->seq_number = rand(); // rand % (2^32)
  socket->ack_number = header->seq_number+1;
  socket->state = ESTABLISHED;

  microtcp_header_t synack;
  synack.seq_number = socket->seq_number;
  synack.ack_number = socket->ack_number;
  synack.control = 0;
  synack.control = set_bit(synack.control, 12);
  synack.control = set_bit(synack.control, 14);
  synack.window = MICROTCP_WIN_SIZE;
  synack.data_len = 0;
  synack.future_use0 = 0;
  synack.future_use1 = 0;
  synack.future_use2 = 0;
  synack.checksum = crc32(&synack, sizeof(synack));

  socket->seq_number += sizeof(synack);

  sendto(socket->sd, &synack, sizeof(synack), &src_addr, &src_addr_length);
  return socket->sd;
}
//TODO: check return value of checksum and sendto
int
microtcp_shutdown (microtcp_sock_t *socket, int how)
{
  microtcp_header_t client_fin, server_ack, *server_header, *client_ack, *client_finack;

  if(socket->state == CLOSING_BY_PEER){

    server_ack.control = 0;
    server_ack.control = set_bit(client_fin.control, 12); // set ACK bit to 1
    server_ack.control = set_bit(client_fin.control, 15); // set FIN bit to 1
    server_ack.ack_number = socket->seq_number + 1;
    server_ack.seq_number = socket->seq_number;
    server_ack.checksum =  crc32(&client_fin, sizeof(client_fin));
    server_ack.window = MICROTCP_WIN_SIZE;
    server_ack.data_len = 0;
    server_ack.future_use0 = 0;
    server_ack.future_use1 = 0;
    server_ack.future_use2 = 0;

    sendto(socket->sd, &server_ack, sizeof(server_ack), 0, socket->server_addr, socket->server_addr_len);

    recvfrom(socket->sd, socket->recvbuf, MICROTCP_RECVBUF_LEN, MSG_WAITALL, socket->server_addr, socket->server_addr_len);
    server_header = socket->recvbuf;
    socket->seq_number += 1;

    if(server_header->seq_number != socket->ack_number && server_header->ack_number != socket->seq_number){
      perror("error");
      return socket->sd;
    }

  }else{

    client_fin.control = 0;
    client_fin.control = set_bit(client_fin.control, 12); // set ACK bit to 1
    client_fin.control = set_bit(client_fin.control, 15); // set FIN bit to 1
    client_fin.ack_number = socket->ack_number;
    client_fin.seq_number = socket->seq_number;
    client_fin.checksum =  crc32(&client_fin, sizeof(client_fin));
    client_fin.window = MICROTCP_WIN_SIZE;
    client_fin.data_len = 0;
    client_fin.future_use0 = 0;
    client_fin.future_use1 = 0;
    client_fin.future_use2 = 0;

    /* send FIN ACK to server */
    sendto(socket->sd, &client_fin, sizeof(client_fin), 0, socket->server_addr, socket->server_addr_len);
    socket->seq_number += 1;

    recvfrom(socket->sd, socket->recvbuf, MICROTCP_RECVBUF_LEN, MSG_WAITALL, socket->server_addr, socket->server_addr_len);
    client_ack = socket->recvbuf;
    
    if(client_ack->ack_number != client_fin.seq_number){
        perror("error");
        socket->state = INVALID;
        return socket->sd;
    }

    recvfrom(socket->sd, socket->recvbuf, MICROTCP_RECVBUF_LEN, MSG_WAITALL, socket->server_addr, socket->server_addr_len);
    client_finack = socket->recvbuf;

    if((get_bit(client_finack->control, 12) == 0) && (get_bit(client_finack->control, 15) == 0)){
        perror("error");
        socket->state = INVALID;
        return socket->sd;
    }

    if(client_finack->ack_number)

  }

  /* this is a test push */
}

ssize_t
microtcp_send (microtcp_sock_t *socket, const void *buffer, size_t length,
               int flags)
{
  /* Your code here */
}

ssize_t
microtcp_recv (microtcp_sock_t *socket, void *buffer, size_t length, int flags)
{
  /* Your code here */
}

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
#include <string.h>
#include <sys/time.h>
#include <netinet/in.h>
#include "helper.h"




microtcp_sock_t
microtcp_socket (int domain, int type, int protocol)
{
  microtcp_sock_t s;
  if ((s.sd = socket(domain, SOCK_DGRAM, IPPROTO_UDP)) == -1){
    perror("opening socket");
    s.state = INVALID;
    return s;
  }
  
  s.packets_send = 0;
  s.packets_received = 0;
  s.packets_lost = 0;
  s.bytes_send = 0;
  s.bytes_received = 0;
  s.bytes_lost = 0;
  
  struct timeval timeout;
  timeout.tv_sec = 0;
  timeout.tv_usec = MICROTCP_ACK_TIMEOUT_US;

  s.state = UNKNOWN;

  struct timeval *timeout = malloc (sizeof(struct timeval));
  timeout->tv_sec = 0;
  timeout->tv_usec = MICROTCP_ACK_TIMEOUT_US ;
  if (setsockopt ( receive_socket , SOL_SOCKET ,SO_RCVTIMEO , &timeout ,sizeof ( struct timeval )) < 0)
  {
    perror("adding timeout");
    s.state = INVALID;
    return s;
  }

  return s;
}




int
microtcp_bind (microtcp_sock_t *socket, const struct sockaddr *address,
               socklen_t address_len)
{ 
  int rv;
  if((rv = bind(socket->sd, address, address_len)) == -1){
    perror("TCP bind");
  }
  
  return rv;
}




/* Calculates checksum of header recv_header
   Returns 1 if checksum calculated is equal to 
   checksum field of header else returns 0 */

int
microtcp_connect (microtcp_sock_t *socket, const struct sockaddr *address,
                  socklen_t address_len)
{
  microtcp_header_t syn, synack, ack;
  struct sockaddr src_addr;
  socklen_t src_addr_length;
  ssize_t bytes_sent, ret;
  char tmp_buf[MICROTCP_RECVBUF_LEN];

  srand(time(NULL));
  socket->seq_number = rand();  // create random sequence number

  /* create the header for the 1st step of the 3-way handshake (SYN segment) */
  syn = make_header(socket->seq_number, 0, 0, 0, 0, 0, 1, 0);
  //syn->checksum = crc32(&synack, sizeof(synack));                             //add checksum
  bytes_sent = sendto(socket->sd, &syn, sizeof((syn)), MSG_CONFIRM, address, address_len); //send segment
  
  if(bytes_sent != sizeof(syn))
  {
    perror("none or not all bytes of syn were sent\n"); 
    socket->state = INVALID;
    return socket->sd;
  } 
  socket->seq_number += 1;
  socket->packets_send += 1;
  socket->bytes_send += bytes_sent;

  //wait to receive the SYNACK from the specific address
  do{
    ret = recvfrom(socket->sd, tmp_buf, MICROTCP_RECVBUF_LEN, MSG_WAITALL, &src_addr, &src_addr_length);
  }while(!is_equal_addresses(*address, src_addr));
  
  synack = get_hbo_header(tmp_buf);

  // received segment
  if(ret<=0){
    socket->state = INVALID;
    return socket->sd;
  }

  // check if checksum in received header is valid
  if(!is_checksum_valid(socket->recvbuf, ret)){
    socket->state = INVALID;
    return socket->sd;
  }

  // check that SYN and ACK bits are set to 1
  // check if ACK_received = SYN_sent + 1
  if( !is_header_control_valid(&synack, 1, 0, 1, 0)
   || synack.ack_number != socket->seq_number)
  {
    socket->state = INVALID;
    return socket->sd;
  }

  //received valid SYNACK
  if (connect(socket->sd, address, address_len) == -1)
  {
    socket->state = INVALID;
    perror("connect");
    return socket->sd;
  }

  socket->address           = *address;
  socket->address_len       = address_len;

  socket->recvbuf           = malloc(MICROTCP_RECVBUF_LEN * sizeof(uint8_t));
  socket->state             = ESTABLISHED;
  socket->ack_number        = synack.seq_number + 1;
  socket->cwnd              = 1;
  socket->ssthresh          = MICROTCP_INIT_SSTHRESH;
  socket->congestion_control_state = SLOW_START;  

  //make header of last ack
  ack = make_header(socket->seq_number, socket->ack_number, MICROTCP_WIN_SIZE, 0, 1, 0, 0, 0);
  //ack->checksum = crc32(&synack, sizeof(synack)); //add checksum

  //send last ack
  bytes_sent = sendto(socket->sd, &ack, sizeof(ack), MSG_CONFIRM, address, address_len);
  if(bytes_sent != sizeof(ack)){
    socket->state = INVALID;
    perror("none or not all ack bytes were sent");
    return socket->sd;
  } 
  socket->seq_number += 1; 

  return socket->sd;
}





/* microtcp.h: microtcp_accept returns 0 on success */

int
microtcp_accept (microtcp_sock_t *socket, struct sockaddr *address,
                 socklen_t address_len)
{
  socket->recvbuf = malloc(MICROTCP_RECVBUF_LEN * sizeof(uint8_t));
  socket->buf_fill_level = 0;
  socket->init_win_size = MICROTCP_WIN_SIZE;
  socket->curr_win_size = MICROTCP_WIN_SIZE;
  
  microtcp_header_t syn, synack, ack;
  struct sockaddr src_addr;
  socklen_t src_addr_length;
  ssize_t bytes_sent, ret; 

  //receive SYN segment from any address
  do
  {
    ret = recvfrom(socket->sd, socket->recvbuf, MICROTCP_RECVBUF_LEN, MSG_WAITALL, &src_addr, &src_addr_length);
    if (ret > 0)
      syn = get_hbo_header(socket->recvbuf);
  } while (!is_header_control_valid(&syn, 0, 0, 1, 0));
  
  //received SYN segment

  // checksum validation
  if(!is_checksum_valid(socket->recvbuf, ret)){
    perror("checksum is invalid");
    socket->state = INVALID;
    return socket->sd;
  }

  //received valid SYN segment
  srand(time(NULL));
  socket->seq_number = rand(); //create random sequence number
  socket->ack_number = syn.ack_number+1;
  socket->init_win_size = syn.window;
  socket->curr_win_size = syn.window;
  socket->address = src_addr;
  socket->address_len = src_addr_length;

  //create header of SYNACK
  synack = make_header(socket->seq_number, socket->ack_number, MICROTCP_WIN_SIZE, 0, 1, 0, 1, 0);
  //synack.checksum = htonl(crc32(&synack, sizeof(synack)));

  //send SYNACK
  bytes_sent = sendto(socket->sd, &synack, sizeof(synack), MSG_CONFIRM, &socket->address, socket->address_len);
  //check that SYNACK was successfully sent
  if (bytes_sent != sizeof(synack))
  {
    socket->state = INVALID;
    perror("none or not all bytes of synack were sent\n");
    return socket->sd;
  }
  socket->seq_number += 1;
  socket->bytes_send += bytes_sent;
  socket->packets_send += 1;

  do
  {
    ret = recvfrom(socket->sd, socket->recvbuf, MICROTCP_RECVBUF_LEN, MSG_WAITALL, &src_addr, &src_addr_length);
  } while (!is_equal_addresses(socket->address, src_addr));
  
  //recvfrom failed
  if (ret <= 0)
  {
    socket->state = INVALID;
    perror("none or not all bytes of ACK were received\n");
    return socket->sd;
  }

  ack = get_hbo_header(socket->recvbuf);

  if(!is_checksum_valid(socket->recvbuf, ret)){
    perror("checksum is invalid");
    socket->state = INVALID;
    return socket->sd;
  }

  //check ACK bit
  if(!is_header_control_valid(&ack, 1, 0, 0, 0))
  {
    socket->state = INVALID;
    perror("failed to accept connection\n");
    return socket->sd;
  }

  if (connect(socket->sd, socket->address, socket->address_len) == -1)
  {
    socket->state = INVALID;
    perror("connect");
    return socket->sd;
  }

  socket->state = ESTABLISHED;
  socket->ack_number = ack.seq_number+1;
  
  return socket->sd;
}




int
microtcp_shutdown (microtcp_sock_t *socket, int how)
{
  microtcp_header_t finack, ack;
  ssize_t ret;
  uint32_t checksum_received, checksum_calculated;

  if(how == SHUT_RDWR){

    //SEND FINACK, RECEIVE ACK
    /* create FIN ACK segment */
    finack = make_header(socket->seq_number, socket->ack_number, MICROTCP_RECVBUF_LEN-socket->buf_fill_level, 0, 1, 0, 0, 1);
    //finack.checksum = htonl(crc32(&finack, sizeof(finack)));
    
    /* send FIN ACK to client */
    ret = send(socket->sd, &finack, sizeof(finack), 0);
    /* server creates FIN ACK segment */

    /* if sendto returned error value or not all header bytes were sent return invalid socket */
    if(ret != sizeof(finack))
    {
      socket->state = INVALID;
      return socket->sd;
    }

    /* wait to receive ACK from client */
    ret = recv(socket->sd, socket->recvbuf, MICROTCP_RECVBUF_LEN, MSG_WAITALL);
    
    /* if recvfrom returned error value or not all header bytes were received return invalid socket */
    if(ret <= 0)
    {
      socket->state = INVALID;
      return socket->sd;
    }

    /* ACK header received in recv buffer */
    //  checksum_received = ntohl(server_header->checksum);
      
    /* check if checksum is valid */
    if(!is_checksum_valid(socket->recvbuf, ret))
    {
        socket->state = INVALID;
        return socket->sd;
      }
    ack = get_hbo_header(socket->recvbuf);

    /* check that seq number and ack number are valid */
    if(ack.seq_number != socket->ack_number || ack.ack_number != socket->seq_number
    || !is_header_control_valid(&ack, 1, 0, 0, 0))
    {
      perror("error");
      socket->state = INVALID;
      return socket->sd;
    }
    socket->seq_number += 1;

    //RECEIVE FINACK, SEND ACK
    if(socket->state != CLOSING_BY_PEER){

      socket->state = CLOSING_BY_HOST;
      
      /* wait to receive FIN ACK */
      ret = recv(socket->sd, socket->recvbuf, MICROTCP_RECVBUF_LEN, MSG_WAITALL);

      if(ret<=0)
      {
        socket->state = INVALID;
        return socket->sd;       
      }

      /* check if checksum is valid */
      if(!is_checksum_valid(socket->recvbuf, ret)){
        socket->state = INVALID;
        return socket->sd;
      }

      finack = get_hbo_header(socket->recvbuf);

      /* check that FIN and ACK bits are set to 1 */
      if(finack.ack_number != socket->seq_number ||
      !is_header_control_valid(&finack, 1,0,0,1)){
        perror("error");
        socket->state = INVALID;
        return socket->sd;
      }

      socket->ack_number = finack.seq_number + 1;

      /* client creates ACK segment to send to server */
      ack = make_header(socket->seq_number, socket->ack_number, MICROTCP_RECVBUF_LEN-socket->buf_fill_level, 0, 1, 0, 0, 0);
      //ack.checksum =  crc32(&ack, sizeof(ack));

      /* send ACK to server */
      ret = send(socket->sd, &ack, sizeof(ack), 0);
      
      /* if sendto returned error value or not all header bytes were sent return invalid socket */
      if(ret < 0){
          socket->state = INVALID;
          return socket->sd;
      }
    }
    
    socket->state = CLOSED;
    free(socket->recvbuf);
    return socket->sd;
  }
  return socket->sd;
}



ssize_t
microtcp_send (microtcp_sock_t *socket, const void *buffer, size_t length,
               int flags)
{
  int                 i, segments_count, dup;
  size_t              last_valid_ack, tmp_cwnd, byte_limit;
  ssize_t             ret;
  uint8_t           **segments;
  uint32_t            tmp_data_len;
  uint64_t            bytes_sent;
  microtcp_header_t   tmp_header;
  int wait;

  while (bytes_sent < length)
  {
    tmp_cwnd = socket->cwnd;
    byte_limit = min (min (socket->curr_win_size, socket->cwnd), length-bytes_sent);
    
    /*probe till window!=0*/
    while (byte_limit == 0)
    {
      ret = flow_control_probe(socket);

      if(ret == -1)
      {
        microtcp_shutdown(socket,  SHUT_RDWR);
        return;
      }
      if(ret)
        byte_limit = min (min (socket->curr_win_size, socket->cwnd), length-bytes_sent);
    }
    
    segments_count = make_segments(socket, segments, buffer+bytes_sent, byte_limit);
    send_segments(socket, segments, segments_count);
    
    for (i=0; i<segments_count; i++)
    {    
      if (!get_valid_segment(socket, socket->recvbuf, sizeof(microtcp_header_t)))
      {
        enter_slow_start(socket);
        /*retransmit*/
        break;
      }
      
      tmp_header = get_hbo_header(socket->recvbuf));

      /* is it a FINACK? */
      if (is_header_control_valid(&tmp_header, 1, 0, 0, 1))
      { 
        microtcp_shutdown(socket,  SHUT_RDWR);
        return;
      }

      /* is it not an ACK? */
      if (!is_header_control_valid(tmp_header, 1, 0, 0, 0))
      {
        /* wait for the same ACK again */
        --i;
        continue;
      }
      
      /* update current window size to what the receiver sent us */
      socket->curr_win_size = tmp_header.window;

      /* if ack_number is not what was expected */
      if (tmp_header.ack_number != socket->seq_number)
      {
        if(dup==3)
        {
          /* 3rd duplicate ACK */
          dup = 0;
          fast_retransmit(socket);
          /* retransmit */
          break;
        }
        if (tmp_header.ack_number == last_valid_ack)
        {
          /* a duplicate ACK*/
          dup++;
          /* wait for the same ACK again*/
          --i;
          continue;
        }
        else 
        {
          /*what happens if ack is not what was expected and not a duplicate?*/
          perror("This is not supposed to happen!");
        }
      }
      else 
      { 
        tmp_data_len = ((microtcp_header_t*)segments[i])->data_len;
        
        /* update sockets fields */
        bytes_sent += tmp_data_len;

        /* update last valid acknowledgement number */
        last_valid_ack = socket->seq_number;
        
        /* update exepcted sequence number */
        socket->seq_number += tmp_data_len;

        /* segment sent successfully! */

        /* update congestion control state and variables */
        update_cwnd(socket);
      }
    }
    /* after break we land here */
  }
}




ssize_t
microtcp_recv (microtcp_sock_t *socket, void *buffer, size_t length, int flags)
{
  ssize_t bytes_received;
  microtcp_header_t header;
  int i=0;

  bytes_received = recv(socket->sd, socket->recvbuf, MICROTCP_RECVBUF_LEN,/*TODO:what's this?*/ flags);

  if(bytes_received<0)
    return -1;

  header = get_hbo_header(buffer);

  //copy the data to the buffer
  for (i=0; i<header.data_len; i++)
  {
    buffer[i] = socket->recvbuf[sizeof(header)+i];
  }

  //sends appropriate ACK
  return send_ack(socket, socket->recvbuf, bytes_received);
}

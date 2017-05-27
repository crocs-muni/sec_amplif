/**
 * Copyright (c) 2017 CRoCS
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * This is the implementation of HD Final protocol for TinyOS platform. The protocol is 
 * used to enhance security of link keys established among neighbouring nodes in Wireless
 * Sensor Network (WSN). The detail description of this protocol and all related materials
 * are available through the webpage https://crocs.fi.muni.cz/papers/iot2017.
 **/

#include "HDFinal.h"
#include "AES.h" 		

module HDFinalC {
  uses {
    // Boot interface provides event booted after the node boots
    interface Boot;	        
    
    // Milliseconds timers for control of execution   
    interface Timer<TMilli> as TimerBootDelay;		
    interface Timer<TMilli> as TimerSendNonceMsg;
    interface Timer<TMilli> as TimerTransmitMsg;
    
    // Radio control and respective packets types
    interface SplitControl as RadioControl;
    interface AMSend as AckSend;
    interface Receive as AckReceive;
    interface AMSend as NonceSend;
    interface Receive as NonceReceive;
    interface AMSend as NonceConfSend;
    interface Receive as NonceConfReceive;
    
    // Interface providing random numbers
    interface Random;
    
    // Interface providing the AES256 encryption
    interface AES;
  }
}

implementation {
  /**
   * Definition of global parameters and structures
   **/
	
  /** @brief Number of messages the node sends during the amplification execution. Calculated as 6 * number of neighbours. */
  uint8_t saMsgToBeSent = 0;
	
  /** @brief Number of messages already sent. Iterate from 0 up to saMsgToBeSent - 1. */
  uint8_t saMsgCounter = 0;
	
  /** @brief Pointer to a particular neighbour. The next amplification message will be generated for this neighbour. */
  uint8_t saNextMsgPtr = 0;
	
  /** @brief Every amplification message is send during an interval with length amplifLength / saMsgToBeSent (in milliseconds). */
  uint16_t saMsgInterval = 0;
	
  /** @brief The stack for building the data part when creating a network packet. */
  uint8_t stack[60];
	
  /** @brief The number of neighbouring nodes. */
  uint8_t numNeigh = 0;
	
  /** @brief The table containing information about all the neighbours. */
  neighMember_t neighTable[maxNeigh];
	
  /** @brief Variable used for a random number generated throughout the application. */
  uint16_t randNumber;

  /** @brief The packet header stored during a reliable packet delivery. */
  uint8_t rlHdr;
	
  /** @brief The packet data part stored during a reliable packet delivery.  */
  uint8_t rlSendBuf[60];
	
  /** @brief The length of data part stored during a reliable packet delivery. */
  uint8_t rlSendLen;
	
  /** @brief The number of remaining attempts for reliable packet delivery. */
  uint8_t rlPending = 0; 

  /** @brief Variables for nonce message, nonce confirmation message, and for acknowledgement message. */
  message_t nonceMsg, nonceConfMsg, ackMsg;
	
  /** @brief Indicate whether the node is currently transmitting a message or not */
  bool sending = FALSE;

  /** 
   * @brief Function returning the index within the neighTable structure for the particular neighbour.
   *
   * @param id The ID of the neighbouring node. The returned index belongs to that node.
   **/
  uint8_t getIndex(uint8_t id) {
    uint8_t i;
    for (i = 0; i < numNeigh; i++) {
      if (neighTable[i].id == id) return i;
    }
  }

  /** 
   * @brief The task that transmits a message stored in reliable transmission structure.
   *
   * The task first transmit the message. Second, if there is still some pending repetition
   * (for reliable delivery), the task plan a retransmission timer (TimerTransmitMsg) in 
   * 100 milliseconds.
   **/
  task void transmitMsg() {
    if (rlSendBuf[0] == PKT_NONCE) {
      pktNonce_t* payload = call NonceSend.getPayload(&nonceMsg, sizeof(pktNonce_t));

      if (payload && !sending) {
        payload->senderId = rlSendBuf[1];
        payload->neighId = rlSendBuf[2];
        payload->interNodeId = rlSendBuf[3];
        memcpy(payload->nonce, rlSendBuf+4, 16);

        if (call NonceSend.send(rlHdr, &nonceMsg, sizeof(pktNonce_t)) == SUCCESS) sending = TRUE;
      }	
    } else if (rlSendBuf[0] == PKT_NONCE_CONF) {
      pktNonceConf_t* payload = call NonceConfSend.getPayload(&nonceConfMsg, sizeof(pktNonceConf_t));

      if (payload && !sending) {
        payload->nonceSenderId = rlSendBuf[1];
        payload->nonceNeighId = rlSendBuf[2];

        if (call NonceConfSend.send(rlHdr, &nonceConfMsg, sizeof(pktNonceConf_t)) == SUCCESS) sending = TRUE;
      }
    }

    rlPending--;

    // Plan next restransmission with 100 milisecond delay (if there were not 4 retransmissions already)
    if (rlPending != 0) call TimerTransmitMsg.startOneShot(100);
  }

  /** 
   * @brief Reliable packet delivery - store packet that should be send.
   *
   * The function ensures the reliable packet delivery. The full packet is stored in several 
   * variables. The number of attempts is identified by setting rlPending variable, currently
   * 4 attempts are performed. The actual sending is performed by task transmitMsg.
   *
   * @param hdr The packet header.
   * @param data The data part of packet.
   * @param size The length of data part.
   **/
  void rlSend(uint8_t hdr, const void* data, uint8_t size) {
    rlHdr = hdr;
    memcpy(rlSendBuf, data, size);
    rlSendLen = size;
    rlPending = 4;
    
    post transmitMsg();
  }

  /** @brief The timer plan the message retransmission in case the acknowledgement was not received. */
  event void TimerTransmitMsg.fired() {	
    // Transmit message (if the Ack was not received yet)
    if (rlPending != 0) post transmitMsg();
  }

  /** 
   * @brief Hash function.
   *
   * The function is implemented as AES encryption of nonce by the respective link key.
   *
   * @param inBlock The data that should be encrypted (hashed) - nonce.
   * @param keyValue The current link key for a respective neighbour.
   * @param hash The output of function is stored there.
   **/
  void hashData(uint8_t* inBlock, uint8_t* keyValue, uint8_t* hash) {
    uint8_t m_exp[240];
       
    call AES.keyExpansion(m_exp, (uint8_t*) keyValue);		
    call AES.encrypt(inBlock, m_exp, hash);
  }

  /** 
   * @brief The node booted event.
   *
   * Instructions executed after the node has booted. Initialisation of structures, start 
   * of radio stack, and start the amplification with defined delay.
   **/
  event void Boot.booted() {		  
    uint8_t i;

    // Starts the radio stack
    call RadioControl.start();
		
    // Initialise table of neighbours
    for (i = 0; i < maxNeigh; i++) {
      neighTable[i].id = 0;
      neighTable[i].interNode1 = 0;
      neighTable[i].interNode2 = 0;
      memset(neighTable[i].key, 0, 16);
      memset(neighTable[i].myNonce, 0, 16);  
      neighTable[i].myNonceNew = 0;                        
      memset(neighTable[i].neighNonce, 0, 16);
      neighTable[i].neighNonceNew = 0;	
    }
    
    // Start the amplification process with defined delay
    call TimerBootDelay.startOneShot(amplifStart);	
  }

  /** 
   * @brief Setup the amplification process and inicialize all the amplification variables. 
   *
   * The intermediate nodes for amplification process are determined during this phase. Total 
   * number of amplification messages is calculate and initial link keys are established.
   **/
  event void TimerBootDelay.fired() {		
    distMember_t neighDistsNC[maxNeigh];
		
    uint32_t distance;
		
    uint32_t centralRelDist1;
    uint32_t neighRelDist1;
    uint32_t centralRelDist2;
    uint32_t neighRelDist2;

    uint32_t currentDistance1;
    uint32_t currentDistance2;
    uint32_t minimalDistance1;
    uint32_t minimalDistance2;

    uint8_t i, j, k, l;
    uint8_t interNode1, interNode2;

    // Compute the relative distances based on hybrid designed protocol HD Final parameters and the transmission range
    centralRelDist1 = 0.69 * nodeTransmissionRange;
    neighRelDist1 = 0.98 * nodeTransmissionRange;
    centralRelDist2 = 0.01 * nodeTransmissionRange;
    neighRelDist2 = 0.39 * nodeTransmissionRange;
		
    // Identify node neighbours and respective distances (this simulates the node discovery phase and RSSI measurements for case when the netwrok topology is not known in advance)
    for (i = 0; i < numNodes; i++) { 
      distance = nodesDistTable[TOS_NODE_ID-1][i];
		
      if (distance != 0) {
        neighTable[numNeigh].id = i+1;
        neighDistsNC[numNeigh].id = i+1;
        neighDistsNC[numNeigh].dist = distance;
		      
        numNeigh++;
        if (numNeigh == maxNeigh) break;
      }
    }

    // Calculate the intermediate nodes for every neighbour
    for (i = 0; i < numNeigh; i++) { 

      // Get the neighbours and distances of particular neighbour NP (simulate the data received from the neighbour for case when the netwrok topology is not known in advance) 
      uint8_t numNeighNP = 0;
      distMember_t neighDistsNP[maxNeigh];
      
      for (j = 0; j < numNodes; j++) { 
        distance = nodesDistTable[neighTable[i].id - 1][j];
				
        if (distance != 0) {
          neighDistsNP[numNeighNP].id = j+1;
          neighDistsNP[numNeighNP].dist = distance;

          numNeighNP++;
          if (numNeighNP == maxNeigh) break;
        }
      }

      // Use the direct link for case where is no better neighbour 
      interNode1 = neighTable[i].id;
      interNode2 = neighTable[i].id;

      minimalDistance1 = 2 * pow(nodeTransmissionRange, 2);
      minimalDistance2 = 2 * pow(nodeTransmissionRange, 2);

      // Identify the common neighbours
      for (k = 0; k < numNeigh; k++) {          
        for (l = 0; l < numNeighNP; l++) {
        
          if (neighDistsNC[k].id == neighDistsNP[l].id) {

            currentDistance1 = 0;
            currentDistance2 = 0;
          
            if (neighDistsNC[k].dist > centralRelDist1) {
              currentDistance1 += (neighDistsNC[k].dist - centralRelDist1)*(neighDistsNC[k].dist - centralRelDist1);
            } else {
              currentDistance1 += (centralRelDist1 - neighDistsNC[k].dist)*(centralRelDist1 - neighDistsNC[k].dist);
            }

            if (neighDistsNP[l].dist > neighRelDist1) {
              currentDistance1 += (neighDistsNP[l].dist - neighRelDist1)*(neighDistsNP[l].dist - neighRelDist1);
            } else {
              currentDistance1 += (neighRelDist1 - neighDistsNP[l].dist)*(neighRelDist1 - neighDistsNP[l].dist);
            }
						
            if (currentDistance1 <= minimalDistance1) {
              minimalDistance1 = currentDistance1;
              interNode1 = neighDistsNC[k].id;
            }

            if (neighDistsNC[k].dist < centralRelDist2) {
              currentDistance2 += (neighDistsNC[k].dist - centralRelDist2)*(neighDistsNC[k].dist - centralRelDist2);
            } else {
              currentDistance2 += (centralRelDist2 - neighDistsNC[k].dist)*(centralRelDist2 - neighDistsNC[k].dist);
            }

            if (neighDistsNP[l].dist < neighRelDist2) {
              currentDistance2 += (neighDistsNP[l].dist - neighRelDist2)*(neighDistsNP[l].dist - neighRelDist2);
            } else {
              currentDistance2 += (neighRelDist2 - neighDistsNP[l].dist)*(neighRelDist2 - neighDistsNP[l].dist);
            }
						
            if (currentDistance2 <= minimalDistance2) {
              minimalDistance2 = currentDistance2;
              interNode2 = neighDistsNC[k].id;
            }   
          }
        }
      }

      // Store the final interNode 1 and interNode 2
      neighTable[i].interNode1 = interNode1;
      neighTable[i].interNode2 = interNode2;
    }

    // Calculate the total number of amplification messages to be sent, message interval and the neighbour for the first amplification attempt
    saMsgToBeSent = numNeigh * 6;
    saMsgInterval = amplifLength / saMsgToBeSent;
    for (i = 0; i < numNeigh; i++) {
      if (neighTable[i].id > TOS_NODE_ID) {
        saNextMsgPtr = i;
        break;
      }
    }
    randNumber = (call Random.rand16()) % saMsgInterval;
		
    // TO_BE_CHANGED Set the initial keys for my neighbours. 
    for (i = 0; i < numNeigh; i++) {
      if (TOS_NODE_ID < neighTable[i].id) {
        neighTable[i].key[0] = TOS_NODE_ID;
        neighTable[i].key[4] = neighTable[i].id;
      } else {	
        neighTable[i].key[0] = neighTable[i].id;
        neighTable[i].key[4] = TOS_NODE_ID;      
      }
    }

    // Plan the process of sending nonce messages
    call TimerSendNonceMsg.startOneShot(randNumber);
  }

  /** 
   * @brief Generation of nonce message and passing the message to the reliable transmission. 
   *
   * The nonce message is generated. After passing to reliable transmission, the next 
   * timer (TimerSendNonceMsg) is used to plan sending of the next nonce message until all
   * the nonce messages are transmitted.
   **/	
  task void sendNonceMsg() {
    uint8_t i;
    uint8_t nonce[16];
    uint8_t header;

    // Generate the nonce
    for (i = 0; i < 16; i++) {
      nonce[i] = call Random.rand16() % 256;
    }

    // Set the destination / intermediate node
    if (saMsgCounter % (numNeigh*2) < numNeigh) {
      header = neighTable[saNextMsgPtr].interNode1;
      stack[3] = neighTable[saNextMsgPtr].interNode1;    
    } else {
      header = neighTable[saNextMsgPtr].interNode2;
      stack[3] = neighTable[saNextMsgPtr].interNode2;
    }
	    
    // Set packet type
    stack[0] = PKT_NONCE;
	    
    // Set source and neighbouring node
    stack[1] = TOS_NODE_ID;
    stack[2] = neighTable[saNextMsgPtr].id;

    // Assign the nonce
    memcpy(stack+4, nonce, 16);

    // Store the nonce for key update
    memcpy(neighTable[saNextMsgPtr].myNonce, nonce, 16);
    neighTable[saNextMsgPtr].myNonceNew = 1;

    // Pass the message to the reliable send
    rlSend(header, stack, 20);

    // Increment all counters
    saNextMsgPtr = (saNextMsgPtr + 1) % numNeigh;
    saMsgCounter++;
    randNumber = (call Random.rand16()) % saMsgInterval;

    // Plan sending another message
    if (saMsgCounter < saMsgToBeSent) call TimerSendNonceMsg.startOneShotAt(0, (uint32_t)amplifStart + (uint32_t)saMsgCounter * (uint32_t)saMsgInterval + (uint32_t)randNumber);
  }

  /** 
   * @brief Timer for controll of generation and sending of nonce messages. 
   *
   * The timer first check whether there is some pending message for reliable transmission.
   * In a positive case, the next check is planned again in 10 milliseconds. In a negative
   * case, the task generating and sending the nonce message is posted.
   **/	
  event void TimerSendNonceMsg.fired() {
    if (rlPending == 0) {
      // There is nothing else to reliably send, post the task sendinding the next nonce message
      post sendNonceMsg();
    } else {
      // There is another message to send, plan the check again with 10 millisecond delay
      call TimerSendNonceMsg.startOneShot(10);
    }
  }

  /** 
   * @brief Acknowledgement message is received.
   *
   * The acknowledgement ensures the reliable packet delivery. After the acknowledgement is 
   * received, the rlPending is set to 0 and packet is not re-sent again. Moreover, if the 
   * acknowledgement was received for nonce confirmation, the link key is updated with 
   * respective neighbour. 
   **/
  event message_t * AckReceive.receive(message_t *msg, void *payload, uint8_t len) {
    pktAck_t* nmsg = payload;
    uint8_t neighIndex = getIndex(nmsg->senderId);
    uint8_t hash[16];

    if (rlPending != 4) {
      rlPending = 0;
    }

    // Update the key, if the original message was a nonce confirmation packet
    if (rlSendBuf[0] == PKT_NONCE_CONF && neighTable[neighIndex].neighNonceNew == 1) {
      hashData(neighTable[neighIndex].neighNonce, neighTable[neighIndex].key, hash);
      neighTable[neighIndex].neighNonceNew = 0;
      memcpy(neighTable[neighIndex].key, hash, 16);
    }

    return msg;
  }

  /** 
   * @brief Nonce message is received.
   *
   * The nonce message is either processed (in case of neighbouring node) or resent (in 
   * case of intermediate node). Finally, the acknowledgement is sent to the sender of
   * the message. 
   **/
  event message_t * NonceReceive.receive(message_t *msg, void *payload, uint8_t len) {
    pktNonce_t* nmsg = payload;
    pktAck_t* ackPayload = call AckSend.getPayload(&ackMsg, sizeof(pktAck_t));
		
    uint8_t header;
    uint8_t neighIndex;
    
    // srcAddress is used to sent the acknowledgement
    uint8_t srcAddress;

    // If I am the neighbouring node, process the packet
    if (nmsg->neighId == TOS_NODE_ID) {
      neighIndex = getIndex(nmsg->senderId);
      srcAddress = nmsg->interNodeId;

      if (memcmp(nmsg->nonce, neighTable[neighIndex].neighNonce, 16) != 0) {
        // Store the nonce to neighNonce field for further update
        memcpy(neighTable[neighIndex].neighNonce, nmsg->nonce, 16);
        neighTable[neighIndex].neighNonceNew = 1;

        // Send confirmation to neighbouring node
        header = nmsg->senderId;
  
        stack[0] = PKT_NONCE_CONF;
        stack[1] = nmsg->senderId;   // Neighbouring node, originator of nonce 
        stack[2] = nmsg->neighId;    // My node ID
          
        // Pass the message to the reliable send
        rlSend(header, stack, 3);
      }
    } else if (nmsg->interNodeId == TOS_NODE_ID && (rlPending == 0 || rlSendBuf[0] != PKT_NONCE_CONF)) {
      // If I am the intermediate node, resend the packet
      header = nmsg->neighId;
      srcAddress = nmsg->senderId;

      stack[0] = PKT_NONCE;
      stack[1] = nmsg->senderId;
      stack[2] = nmsg->neighId;
      stack[3] = nmsg->interNodeId;
        
      memcpy(stack+4, nmsg->nonce, 16);

      // Pass the message to the reliable send
      rlSend(header, stack, 20);
    }

    // Sent acknowledgement for original packet
    if (ackPayload && !sending) {
      ackPayload->senderId = TOS_NODE_ID;
      if (call AckSend.send(srcAddress, &ackMsg, sizeof(pktAck_t)) == SUCCESS) sending = TRUE;
    }

    return msg;
  }

  /** 
   * @brief Nonce confirmation message is received.
   *
   * The link key is updated for a particular neighbour. The acknowledgement is sent to 
   * the sender of the message. 
   **/
  event message_t * NonceConfReceive.receive(message_t *msg, void *payload, uint8_t len) {
    pktNonceConf_t* nmsg = payload;
    pktAck_t* ackPayload = call AckSend.getPayload(&ackMsg, sizeof(pktAck_t));

    uint8_t neighIndex = getIndex(nmsg->nonceNeighId);
    uint8_t srcAddress = nmsg->nonceNeighId;
    uint8_t hash[16];
    
    // If the nonce was not yet used for key update, do the key update
    if (neighTable[neighIndex].myNonceNew == 1) {
      hashData(neighTable[neighIndex].myNonce, neighTable[neighIndex].key, hash);
      neighTable[neighIndex].myNonceNew = 0;
      memcpy(neighTable[neighIndex].key, hash, 16);
    }

    // Sent acknowledgement for original packet
    if (ackPayload && !sending) {
      ackPayload->senderId = TOS_NODE_ID;
      if (call AckSend.send(srcAddress, &ackMsg, sizeof(pktAck_t)) == SUCCESS) sending = TRUE;
    }

    return msg;
  }
  
  event void AckSend.sendDone(message_t *msg, error_t error) {sending = FALSE;}
  event void NonceSend.sendDone(message_t *msg, error_t error) {sending = FALSE;}
  event void NonceConfSend.sendDone(message_t *msg, error_t error) {sending = FALSE;}
	
  event void RadioControl.startDone(error_t error) {}
  event void RadioControl.stopDone(error_t error) {}
}
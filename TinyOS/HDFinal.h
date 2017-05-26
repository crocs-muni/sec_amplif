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
 * This is the header file of HD Final protocol for TinyOS platform. The protocol is 
 * used to enhance security of link keys established among neighbouring nodes in Wireless
 * Sensor Network (WSN). The detail description of this protocol and all related materials
 * are available through the webpage https://crocs.fi.muni.cz/papers/iot2017.
 **/

#ifndef HDFINAL_H
#define HDFINAL_H

/**
 * TO_BE_CHANGED Parameters dependent on usage in a particular network. 
 **/
enum {	
  /** @brief Total number of nodes in the network */
  numNodes = 24,
	
  /** @brief The maximum number of neighbours of particular node */
  maxNeigh = 5,
	
  /** @brief The length of amplification process in milliseconds */
  amplifLength = 300000,
	
  /** @brief The delay for amplification process after the node booted in milliseconds */
  amplifStart = 10000,
	
  /** @brief The node trasmission range used during the hybrid design protocol setup (referenced length) in millimeters */
  nodeTransmissionRange = 13000,
};

/** @brief The definition of network topology. The position [m][n] is the distance of nodes with IDs m - 1 and n - 1. The 0 indicates that nodes are not neighbours. */
static const uint32_t nodesDistTable[24][24] = {{0, 0, 0, 5683, 3640, 4781, 5490, 0, 0, 2200, 0, 0, 5011, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 3315, 373, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 3570, 909, 2203, 2174, 0, 0, 0, 0, 5986, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6543, 0, 0}, {5683, 0, 3570, 0, 4471, 1376, 4888, 7461, 0, 0, 0, 4692, 4580, 0, 0, 0, 0, 0, 0, 9286, 6564, 0, 0, 0}, {3640, 0, 909, 4471, 0, 3100, 1850, 6313, 0, 0, 0, 0, 6782, 0, 0, 0, 0, 0, 0, 0, 7503, 6448, 0, 0}, {4781, 0, 2203, 1376, 3100, 0, 3610, 6740, 6493, 6611, 8327, 5053, 5023, 0, 0, 0, 0, 0, 0, 8588, 6459, 6844, 0, 0}, {5490, 0, 2174, 4888, 1850, 3610, 0, 0, 6495, 7690, 0, 8113, 8172, 0, 0, 0, 0, 0, 0, 6160, 6000, 4613, 0, 0}, {0, 0, 0, 7461, 6313, 6740, 0, 0, 4100, 0, 0, 0, 11764, 0, 0, 0, 0, 0, 0, 1848, 3252, 139, 0, 5263}, {0, 0, 0, 0, 0, 6493, 6495, 4100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5055, 859, 4052, 0, 5711}, {2200, 3315, 0, 0, 0, 6611, 7690, 0, 0, 0, 3450, 4731, 5033, 0, 8733, 4960, 7864, 0, 10833, 0, 12855, 0, 0, 0}, {0, 373, 0, 0, 0, 8327, 0, 0, 0, 3450, 0, 4117, 4379, 5286, 0, 3479, 4858, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 5986, 4692, 0, 5053, 8113, 0, 0, 4731, 4117, 0, 308, 0, 0, 0, 8476, 0, 0, 0, 0, 0, 0, 0}, {5011, 0, 0, 4580, 6782, 5023, 8172, 11764, 0, 5033, 4379, 308, 0, 0, 0, 7832, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5286, 0, 0, 0, 5000, 2200, 2952, 3265, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 8733, 0, 0, 0, 5000, 0, 5462, 2054, 5354, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 4960, 3479, 0, 7832, 2200, 5462, 0, 3759, 5435, 6268, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 7864, 4858, 8476, 0, 2952, 2054, 3759, 0, 3798, 3070, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3265, 5354, 5435, 3798, 0, 2500, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 10833, 0, 0, 0, 0, 0, 6268, 3070, 2500, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 9286, 0, 8588, 6160, 1848, 5055, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4215, 1746, 1780, 0}, {0, 0, 0, 6564, 7503, 6459, 6000, 3252, 859, 12855, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4215, 0, 3200, 5160, 5248}, {0, 0, 6543, 0, 6448, 6844, 4613, 139, 4052, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1746, 3200, 0, 0, 5124}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1780, 5160, 0, 0, 0}, {0, 0, 0, 0, 0, 0, 0, 5263, 5711, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5248, 5124, 0, 0}};

/**
 * Definition of global parameters and structures
 **/

/** @brief The definition of packet types */
enum {
  PKT_ACK = 1,
  PKT_NONCE = 2,
  PKT_NONCE_CONF = 3,
};

/** @brief Structure for nonce packet */
typedef struct pktNonce {
  uint8_t senderId;       // ID of the node that generates the nonce
  uint8_t neighId;        // ID of the neighbouring node (nonce is designated for that node)
  uint8_t interNodeId;    // ID of the intermediate node (node only retransmit the nonce packet)
  uint8_t nonce[16];      // The nonce
} pktNonce_t;

/** @brief Structure for nonce confirmation packet */
typedef struct pktNonceConf {
  uint8_t nonceSenderId;  // ID of the node that generated the nonce
  uint8_t nonceNeighId;   // ID of the neighbouring node (nonce is designated for that node)
} pktNonceConf_t;

/** @brief Structure for the acknowledgement packet */
typedef struct pktAck {
  uint8_t senderId;       // ID of the node that sends acknowledgement
} pktAck_t;

/** @brief Structure for information about one neighbour */
typedef struct neighMember {
  uint8_t id;               // Neighbour ID
  uint8_t interNode1;       // First intermediate node for amplification
  uint8_t interNode2;       // Second intermediate node for amplification
  uint8_t key[16];          // Link key established with neighbouring node
  uint8_t myNonce[16];      // The nonce generated for that neighbour,  will be used after nonce confirmation packet received
  uint8_t myNonceNew;       // Indicator whether the myNonce was already used for key update (multiple confirmation packet received)
  uint8_t neighNonce[16];   // The nonce received for that particular neighbour (multiple nonce packets received)
  uint8_t neighNonceNew;    // Indicator whether the neighNonce was already used for key update (multiple ack packets received)
} neighMember_t;

/** @brief Structure for distance from a particular neighbour */
typedef struct distMember {
  uint8_t id;               // Neighbour ID
  uint32_t dist;            // Distance form that neighbour
} distMember_t;

#endif /* HDFINAL_H */

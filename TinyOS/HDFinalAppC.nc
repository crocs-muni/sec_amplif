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
 * This is the wiring of HD Final protocol for TinyOS platform. The protocol is 
 * used to enhance security of link keys established among neighbouring nodes in Wireless
 * Sensor Network (WSN). The detail description of this protocol and all related materials
 * are available through the webpage https://crocs.fi.muni.cz/papers/iot2017.
 **/
 
configuration HDFinalAppC {
}

implementation {
  components MainC, HDFinalC as App;
  components ActiveMessageC as RadioAM;
  components new TimerMilliC() as TimerBootDelay;
  components new TimerMilliC() as TimerSendNonceMsg;
  components new TimerMilliC() as TimerTransmitMsg;
	
  App.Boot -> MainC;
  App.TimerBootDelay -> TimerBootDelay;
  App.TimerSendNonceMsg -> TimerSendNonceMsg;
  App.TimerTransmitMsg -> TimerTransmitMsg; 
  App.RadioControl -> RadioAM;

  components RandomC;
  App.Random -> RandomC;

  components new AMSenderC(PKT_ACK) as AckSend; 
  components new AMReceiverC(PKT_ACK) as AckReceive;
  App.AckSend -> AckSend;
  App.AckReceive -> AckReceive;

  components new AMSenderC(PKT_NONCE) as NonceSend; 
  components new AMReceiverC(PKT_NONCE) as NonceReceive;
  App.NonceSend -> NonceSend;
  App.NonceReceive -> NonceReceive;

  components new AMSenderC(PKT_NONCE_CONF) as NonceConfSend; 
  components new AMReceiverC(PKT_NONCE_CONF) as NonceConfReceive;
  App.NonceConfSend -> NonceConfSend;
  App.NonceConfReceive -> NonceConfReceive;

  components AESC;
  App.AES->AESC.AES;
}

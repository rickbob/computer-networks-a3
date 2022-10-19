package edu.ut.cs.sdn.vnet.rt;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.MACAddress;

import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.Queue;

import edu.ut.cs.sdn.vnet.Iface;

public class ArpQueueEntry {

  private Ethernet arpRequest;
  private int retryCount;
  private Queue<EthernetQueueEntry> packets;

  public ArpQueueEntry(Ethernet arpRequest) {
    this.arpRequest = arpRequest;
    this.retryCount = 0;
    this.packets = new ConcurrentLinkedQueue<>();
  }

  public void add(Ethernet packet, Iface inIface, MACAddress sourceMac) {
    packets.add(new EthernetQueueEntry(packet, inIface, sourceMac));
  }

  public EthernetQueueEntry poll() {
    return packets.poll();
  }

  public int size() {
    return packets.size();
  }

  public boolean isEmpty() {
    return packets.isEmpty();
  }

  public boolean canResend() {
    return retryCount < 3;
  }

  public Ethernet getArpRequest() {
    return arpRequest;
  }

  public void incrementRetries() {
    this.retryCount++;
  }

  class EthernetQueueEntry {
    private Ethernet packet;
    private Iface inIface;
    private MACAddress sourceMac;

    public EthernetQueueEntry(Ethernet packet, Iface inIface, MACAddress sourceMac) {
      this.packet = packet;
      this.inIface = inIface;
      this.sourceMac = sourceMac;
    }

    public Ethernet getPacket() {
      return packet;
    }

    public Iface getInIface() {
      return inIface;
    }

    public MACAddress getSourceMacAddress() {
      return sourceMac;
    }
  }
  
}

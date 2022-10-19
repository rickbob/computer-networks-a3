package edu.ut.cs.sdn.vnet.rt;

import edu.ut.cs.sdn.vnet.Device;
import edu.ut.cs.sdn.vnet.DumpFile;
import edu.ut.cs.sdn.vnet.Iface;
import edu.ut.cs.sdn.vnet.rt.ArpQueueEntry.EthernetQueueEntry;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.MACAddress;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.ARP;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device {
	/** Routing table for the router */
	private RouteTable routeTable;

	/** ARP cache for the router */
	private ArpCache arpCache;

	// create the queue of packets for each IP address
	private ConcurrentHashMap<Integer, ArpQueueEntry> arpQueue;

	private Thread retryThread;

	/**
	 * Creates a router for a specific host.
	 * 
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile) {
		super(host, logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
		this.arpQueue = new ConcurrentHashMap<>();
		this.retryThread = new Thread() {
			public void run() {
				runRetry();
			}
		};
		retryThread.start();
	}

	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable() {
		return this.routeTable;
	}

	/**
	 * Load a new routing table from a file.
	 * 
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile) {
		if (!routeTable.load(routeTableFile, this)) {
			System.err.println("Error setting up routing table from file "
					+ routeTableFile);
			System.exit(1);
		}

		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}

	/**
	 * Load a new ARP cache from a file.
	 * 
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile) {
		if (!arpCache.load(arpCacheFile)) {
			System.err.println("Error setting up ARP cache from file "
					+ arpCacheFile);
			System.exit(1);
		}

		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.arpCache.toString());
		System.out.println("----------------------------------");
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * 
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface     the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface) {
		System.out.println("*** -> Received packet: " +
				etherPacket.toString().replace("\n", "\n\t"));

		/********************************************************************/
		/* TODO: Handle packets */

		switch (etherPacket.getEtherType()) {
			case Ethernet.TYPE_IPv4:
				this.handleIpPacket(etherPacket, inIface);
				break;
			case Ethernet.TYPE_ARP:
				this.handleArpPacket(etherPacket, inIface);
				// Ignore all other packet types, for now
		}

		/********************************************************************/
	}

	private void handleArpPacket(Ethernet etherPacket, Iface inIface) {
		ARP arpPacket = (ARP) etherPacket.getPayload();
		int targetIp = ByteBuffer.wrap(arpPacket.getTargetProtocolAddress()).getInt();

		// handle ARP request
		if (arpPacket.getOpCode() == ARP.OP_REQUEST) {
			if (targetIp != inIface.getIpAddress())
				return;
			sendPacket(buildARPReply(etherPacket, inIface), inIface);
		} else if (arpPacket.getOpCode() == ARP.OP_REPLY) {
			// create arpCache entry
			int senderIp = ByteBuffer.wrap(arpPacket.getSenderProtocolAddress()).getInt();
			MACAddress senderMAC = MACAddress.valueOf(arpPacket.getSenderHardwareAddress());
			arpCache.insert(senderMAC, senderIp);

			ArpQueueEntry packets = arpQueue.get(senderIp);
			if (packets == null)
				return;
			while (!packets.isEmpty()) {
				Ethernet packet = packets.poll().getPacket();
				packet.setDestinationMACAddress(senderMAC.toBytes());
				sendPacket(packet, inIface);
			}
			arpQueue.remove(senderIp);
		}
	}

	private void handleIpPacket(Ethernet etherPacket, Iface inIface) {
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
			return;

		// Get IP header
		IPv4 ipPacket = (IPv4) etherPacket.getPayload();
		System.out.println("Handle IP packet");

		// Verify checksum
		short origCksum = ipPacket.getChecksum();
		ipPacket.resetChecksum();
		byte[] serialized = ipPacket.serialize();
		ipPacket.deserialize(serialized, 0, serialized.length);
		short calcCksum = ipPacket.getChecksum();
		if (origCksum != calcCksum)
			return;

		// Check TTL
		if (1 == ipPacket.getTtl()) {
			Ethernet icmpEtherPkt = getICMPPacket((byte) 11, (byte) 0, inIface, ipPacket);
			sendPacket(icmpEtherPkt, inIface);
			return;
		}
		ipPacket.setTtl((byte) (ipPacket.getTtl() - 1));

		// Reset checksum now that TTL is decremented
		ipPacket.resetChecksum();

		// Do route lookup and forward
		this.forwardIpPacket(etherPacket, inIface);
	}

	private void forwardIpPacket(Ethernet etherPacket, Iface inIface) {
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4) {
			return;
		}
		System.out.println("Forward IP packet");

		// Get IP header
		IPv4 ipPacket = (IPv4) etherPacket.getPayload();
		int dstAddr = ipPacket.getDestinationAddress();

		// Find matching route table entry
		RouteEntry bestMatch = this.routeTable.lookup(dstAddr);

		// If no entry matched, do nothing
		if (null == bestMatch) {
			Ethernet icmpEtherPkt = getICMPPacket((byte) 3, (byte) 0, inIface, ipPacket);
			sendPacket(icmpEtherPkt, inIface);
			return;
		}

		// If no gateway, then nextHop is IP destination
		int nextHop = bestMatch.getGatewayAddress();
		if (0 == nextHop) {
			nextHop = dstAddr;
		}

		// Set destination MAC address in Ethernet header
		ArpEntry arpEntry = this.arpCache.lookup(nextHop);
		System.out.println("ARP ENTRY: " + arpEntry);
		if (null == arpEntry) {
			System.out.println("Here for " + nextHop);

			Ethernet arpRequest = buildArpRequest(inIface, nextHop);
			// Queue the packet
			ArpQueueEntry nextHopQueue = arpQueue.get(nextHop);
			if (nextHopQueue == null) {
				nextHopQueue = new ArpQueueEntry(arpRequest);
				arpQueue.put(nextHop, nextHopQueue);
				// for (Iface routerIface : this.interfaces.values()) {
				// 	sendPacket(arpRequest, routerIface);
				// }
			}
			etherPacket.setSourceMACAddress(bestMatch.getInterface().getMacAddress().toBytes());
			nextHopQueue.add(etherPacket, inIface);

			// for (Iface routerIface : this.interfaces.values()) {
			// if (routerIface != inIface)
			// sendPacket(arpRequest, routerIface);
			// }
			return;
		}

		// Make sure we don't sent a packet back out the interface it came in

		for (Iface routerIface : this.interfaces.values()) {
			if (routerIface.getIpAddress() == dstAddr) {
				if (ipPacket.getProtocol() == IPv4.PROTOCOL_TCP || ipPacket.getProtocol() == IPv4.PROTOCOL_UDP) {
					Ethernet icmpEtherPkt = getICMPPacket((byte) 3, (byte) 3, inIface, ipPacket);
					sendPacket(icmpEtherPkt, inIface);
				} else if (ipPacket.getProtocol() == IPv4.PROTOCOL_ICMP) {
					ICMP icmpPacket = (ICMP) ipPacket.getPayload();

					// Check if echo request
					if (icmpPacket.getIcmpType() == 8) {
						Ethernet echoReply = buildEchoReply(inIface, etherPacket);
						System.out.println("*** -> Sending echo packet: " +
								echoReply.toString().replace("\n", "\n\t"));
						sendPacket(echoReply, routerIface);
					}
				}

				return;
			}
		}

		Iface outIface = bestMatch.getInterface();
		if (outIface == inIface) {
			return;
		}

		// Set source MAC address in Ethernet header
		etherPacket.setSourceMACAddress(outIface.getMacAddress().toBytes());

		etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());

		this.sendPacket(etherPacket, outIface);
	}

	private Ethernet getICMPPacket(byte type, byte code, Iface inIface, IPv4 originalPacket) {
		Ethernet ether = new Ethernet();
		ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
		ether.setDestinationMACAddress(getICMPDestinationMacAddress(originalPacket, inIface).toBytes());

		IPv4 ip = new IPv4();
		ip.setTtl((byte) 64);
		ip.setProtocol(IPv4.PROTOCOL_ICMP);
		ip.setSourceAddress(inIface.getIpAddress());
		ip.setDestinationAddress(originalPacket.getSourceAddress());

		ICMP icmp = new ICMP();
		icmp.setIcmpType(type);
		icmp.setIcmpCode(code);

		Data data = new Data();
		int headerLength = originalPacket.getHeaderLength() * 4;
		int numBytes = 4 + headerLength + 8;
		byte[] dataArr = new byte[numBytes];
		byte[] ipData = originalPacket.serialize();
		System.arraycopy(ipData, 0, dataArr, 4, headerLength + 8);
		data.setData(dataArr);

		ether.setPayload(ip);
		ip.setPayload(icmp);
		icmp.setPayload(data);

		return ether;
	}

	private Ethernet buildEchoReply(Iface inIface, Ethernet originalEther) {
		IPv4 originalPacket = (IPv4) originalEther.getPayload();

		Ethernet ether = new Ethernet();
		ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
		ether.setDestinationMACAddress(originalEther.getSourceMACAddress());

		IPv4 ip = new IPv4();
		ip.setTtl((byte) 64);
		ip.setProtocol(IPv4.PROTOCOL_ICMP);
		ip.setSourceAddress(originalPacket.getDestinationAddress());
		ip.setDestinationAddress(originalPacket.getSourceAddress());

		ICMP icmp = new ICMP();
		icmp.setIcmpType((byte) 0);
		icmp.setIcmpCode((byte) 0);
		icmp.resetChecksum();

		ether.setPayload(ip);
		ip.setPayload(icmp);

		ICMP echoRequest = (ICMP) originalPacket.getPayload();
		icmp.setPayload(echoRequest.getPayload());

		return ether;
	}

	private MACAddress getICMPDestinationMacAddress(IPv4 originalPacket, Iface inIface) {
		int srcAddr = originalPacket.getSourceAddress();

		// Find matching route table entry
		RouteEntry bestMatch = this.routeTable.lookup(srcAddr);

		// If no entry matched, do nothing
		if (null == bestMatch) {
			System.out.println("bestMatch null");
			return null;
		}

		// If no gateway, then nextHop is IP destination
		int nextHop = bestMatch.getGatewayAddress();
		if (0 == nextHop) {
			nextHop = srcAddr;
		}

		// Set destination MAC address in Ethernet header
		ArpEntry arpEntry = this.arpCache.lookup(nextHop);
		if (null == arpEntry) {
			System.out.println("arpEntry null");
			return null;
		}

		return arpEntry.getMac();
	}

	private Ethernet buildARPReply(Ethernet etherPacket, Iface inIface) {
		ARP arpReq = (ARP) etherPacket.getPayload();
		Ethernet ether = new Ethernet();
		ether.setEtherType(Ethernet.TYPE_ARP);
		ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
		ether.setDestinationMACAddress(etherPacket.getSourceMACAddress());

		ARP arp = new ARP();
		arp.setHardwareType(ARP.HW_TYPE_ETHERNET);
		arp.setProtocolType(ARP.PROTO_TYPE_IP);
		arp.setHardwareAddressLength((byte) Ethernet.DATALAYER_ADDRESS_LENGTH);
		arp.setProtocolAddressLength((byte) 4);
		arp.setOpCode(ARP.OP_REPLY);
		arp.setSenderHardwareAddress(inIface.getMacAddress().toBytes());
		arp.setSenderProtocolAddress(inIface.getIpAddress());
		arp.setTargetHardwareAddress(arpReq.getSenderHardwareAddress());
		arp.setTargetProtocolAddress(arpReq.getSenderProtocolAddress());

		ether.setPayload(arp);
		return ether;
	}

	private Ethernet buildArpRequest(Iface inIface, int nextHop) {
		Ethernet ether = new Ethernet();
		ether.setEtherType(Ethernet.TYPE_ARP);
		ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
		ether.setDestinationMACAddress(MACAddress.valueOf("FF:FF:FF:FF:FF:FF").toBytes());

		ARP arp = new ARP();
		arp.setHardwareType(ARP.HW_TYPE_ETHERNET);
		arp.setProtocolType(ARP.PROTO_TYPE_IP);
		arp.setHardwareAddressLength((byte) Ethernet.DATALAYER_ADDRESS_LENGTH);
		arp.setProtocolAddressLength((byte) 4);
		arp.setOpCode(ARP.OP_REQUEST);
		arp.setSenderHardwareAddress(inIface.getMacAddress().toBytes());
		arp.setSenderProtocolAddress(inIface.getIpAddress());
		arp.setTargetHardwareAddress(MACAddress.valueOf(0).toBytes());
		arp.setTargetProtocolAddress(IPv4.toIPv4AddressBytes(nextHop));

		System.out.println("Destination MAC: " + MACAddress.valueOf("FF:FF:FF:FF:FF:FF").toBytes().length);
		System.out.println("Sender Hardware Address: " + Arrays.toString(arp.getSenderHardwareAddress()));
		System.out.println("Sender Protocol Address: " + Arrays.toString(arp.getSenderProtocolAddress()));
		System.out.println("Target Hardware Address: " + Arrays.toString(arp.getTargetHardwareAddress()));
		System.out.println("Target Protocol Address: " + Arrays.toString(arp.getTargetProtocolAddress()));
		System.out.println("Hardware Length: " + arp.getHardwareAddressLength());
		System.out.println("Protocol Length: " + arp.getProtocolAddressLength());

		ether.setPayload(arp);
		return ether;
	}

	// resend requests in the ArpQueue on a timer
	public void runRetry() {
		while (true) {
			// Run every second
			try {
				Thread.sleep(1000);
			} catch (InterruptedException e) {
				break;
			}

			System.out.println("1 second elapsed");

			for (ArpQueueEntry entry : this.arpQueue.values()) {
				// broadcast the retried ArpEntry
				if (entry.canResend()) {
					System.out.println("Resending...");
					for (Iface routerIface : this.interfaces.values()) {
						sendPacket(entry.getArpRequest(), routerIface);
					}
					entry.incrementRetries();
				} else {
					// clear the queue and send destination unreachable
					System.out.println("Out of retries");
					while (!entry.isEmpty()) {
						ArpQueueEntry.EthernetQueueEntry packetEntry = entry.poll();
						Iface inIface = packetEntry.getInIface();
						IPv4 ipPacket = (IPv4) packetEntry.getPacket().getPayload();
						Ethernet icmpEtherPkt = getICMPPacket((byte) 3, (byte) 1, inIface, ipPacket);
						sendPacket(icmpEtherPkt, inIface);
					}
					// TODO: do we remove the entry from the table?
				}
			}
		}
	}
}

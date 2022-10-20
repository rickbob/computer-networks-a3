package edu.ut.cs.sdn.vnet.rt;

import edu.ut.cs.sdn.vnet.Device;
import edu.ut.cs.sdn.vnet.DumpFile;
import edu.ut.cs.sdn.vnet.Iface;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.MACAddress;
import net.floodlightcontroller.packet.RIPv2;
import net.floodlightcontroller.packet.RIPv2Entry;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.ARP;

import java.nio.ByteBuffer;
import java.util.Iterator;
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

	public void buildRouteTableFromRIP() {
		System.out.println("Building route table using RIP...");
		// initializing the directly reachable subnets via router's interfaces
		for (Iface routerIface : this.interfaces.values()) {
			routeTable.insert(routerIface.getIpAddress(), 0, routerIface.getSubnetMask(),
					routerIface, 0);
		}

		for (Iface routeIface : this.interfaces.values()) {
			Ethernet ripEthernet = buildRIPRequest(routeIface);
			sendPacket(ripEthernet, routeIface);
		}
		new Thread() {
			public void run() {
				runRIPResponse();
			}
		}.start();
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
				IPv4 ipPacket = (IPv4) etherPacket.getPayload();
				if (ipPacket.getProtocol() == IPv4.PROTOCOL_UDP) {
					UDP udpPacket = (UDP) ipPacket.getPayload();
					if (udpPacket.getDestinationPort() == UDP.RIP_PORT) {
						this.handleRIPPacket(etherPacket, inIface);
						break;
					}
				}
				this.handleIpPacket(etherPacket, inIface);
				break;
			case Ethernet.TYPE_ARP:
				this.handleArpPacket(etherPacket, inIface);
				// Ignore all other packet types, for now
		}

		/********************************************************************/
	}

	private void handleRIPPacket(Ethernet etherPacket, Iface inIface) {
		IPv4 ipPacket = (IPv4) etherPacket.getPayload();
		UDP udpPacket = (UDP) ipPacket.getPayload();
		RIPv2 ripPacket = (RIPv2) udpPacket.getPayload();
		System.out.println("Got RIP packet");

		if (ripPacket.getCommand() == RIPv2.COMMAND_REQUEST) {
			// Handle RIP request by sending response
			Ethernet rip = buildRIPResponse(inIface, inIface.getMacAddress().toString(),
					IPv4.fromIPv4Address(inIface.getIpAddress()));
			sendPacket(rip, inIface);
		} else if (ripPacket.getCommand() == RIPv2.COMMAND_RESPONSE) {
			// Handle RIP response by updating this router's route table
			System.out.println("GETTING RIP RESPONSE");

			for (RIPv2Entry ripEntry : ripPacket.getEntries()) {
				int address = ripEntry.getAddress();
				int mask = ripEntry.getSubnetMask();
				int gwIp = ipPacket.getSourceAddress();
				// if (gwIp == 0) {
					// gwIp = inIface.getIpAddress();
				// }
				int newDistance = ripEntry.getMetric() + 1;

				System.out.println("Address: " + IPv4.fromIPv4Address(address));
				System.out.println("Mask: " + IPv4.fromIPv4Address(mask));
				System.out.println("GW: " + IPv4.fromIPv4Address(gwIp));
				System.out.println("Distance: " + newDistance);

				RouteEntry curr = routeTable.lookup(address);
				if (curr == null) {
					System.out.println("GETTING NEW ROUTETABLE ENTRY");
					routeTable.insert(address, gwIp, mask, inIface, newDistance);
				} else if (newDistance <= curr.getDistance()) {
					routeTable.update(address, gwIp, mask, newDistance, inIface);
				}
			}

			System.out.println(routeTable.toString());
		}

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
			Ethernet icmpEtherPkt = getICMPPacket((byte) 11, (byte) 0, inIface, ipPacket, null);
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
			Ethernet icmpEtherPkt = getICMPPacket((byte) 3, (byte) 0, inIface, ipPacket, etherPacket.getSourceMAC());
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
			System.out.println("Here for: " + IPv4.fromIPv4Address(nextHop));

			Ethernet arpRequest = buildArpRequest(inIface, nextHop);
			// Queue the packet
			ArpQueueEntry nextHopQueue = arpQueue.get(nextHop);
			if (nextHopQueue == null) {
				nextHopQueue = new ArpQueueEntry(arpRequest);
				arpQueue.put(nextHop, nextHopQueue);
				// for (Iface routerIface : this.interfaces.values()) {
				// sendPacket(arpRequest, routerIface);
				// }
			}
			nextHopQueue.add(etherPacket, inIface, etherPacket.getSourceMAC());
			etherPacket.setSourceMACAddress(bestMatch.getInterface().getMacAddress().toBytes());

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
					Ethernet icmpEtherPkt = getICMPPacket((byte) 3, (byte) 3, inIface, ipPacket, null);
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

	private Ethernet getICMPPacket(byte type, byte code, Iface inIface, IPv4 originalPacket, MACAddress destMac) {
		Ethernet ether = new Ethernet();
		ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
		if (destMac == null) {
			ether.setDestinationMACAddress(getICMPDestinationMacAddress(originalPacket, inIface).toBytes());
		} else {
			ether.setDestinationMACAddress(destMac.toBytes());
		}

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
		ether.setDestinationMACAddress("FF:FF:FF:FF:FF:FF");

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

		ether.setPayload(arp);
		return ether;
	}

	public Ethernet buildRIPRequest(Iface outFace) {
		Ethernet ether = new Ethernet();
		ether.setSourceMACAddress(outFace.getMacAddress().toBytes());
		ether.setDestinationMACAddress("FF:FF:FF:FF:FF:FF");
		ether.setEtherType(Ethernet.TYPE_IPv4);

		IPv4 ip = new IPv4();
		ip.setSourceAddress(outFace.getIpAddress());
		ip.setDestinationAddress("224.0.0.9");
		ip.setProtocol(IPv4.PROTOCOL_UDP);

		UDP udp = new UDP();
		udp.setDestinationPort((short) UDP.RIP_PORT);
		udp.setSourcePort((short) UDP.RIP_PORT);

		RIPv2 rip = new RIPv2();
		rip.setCommand(RIPv2.COMMAND_REQUEST);
		// for (RouteEntry routeEntry : routeTable.getRouteEntries()) {
		// RIPv2Entry riPv2Entry = new RIPv2Entry(routeEntry);
		// rip.addEntry(riPv2Entry);
		// }

		ether.setPayload(ip);
		ip.setPayload(udp);
		udp.setPayload(rip);

		return ether;
	}

	public Ethernet buildRIPResponse(Iface outFace, String destMAC, String destIP) {
		Ethernet ether = new Ethernet();
		ether.setSourceMACAddress(outFace.getMacAddress().toBytes());
		ether.setDestinationMACAddress(destMAC);
		ether.setEtherType(Ethernet.TYPE_IPv4);

		IPv4 ip = new IPv4();
		ip.setDestinationAddress(destIP);
		ip.setProtocol(IPv4.PROTOCOL_UDP);

		UDP udp = new UDP();
		udp.setDestinationPort((short) UDP.RIP_PORT);
		udp.setSourcePort((short) UDP.RIP_PORT);

		RIPv2 rip = new RIPv2();
		rip.setCommand(RIPv2.COMMAND_RESPONSE);
		for (RouteEntry routeEntry : routeTable.getRouteEntries()) {
			RIPv2Entry riPv2Entry = new RIPv2Entry(routeEntry);
			rip.addEntry(riPv2Entry);
		}

		ether.setPayload(ip);
		ip.setPayload(udp);
		udp.setPayload(rip);

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

			for (ArpQueueEntry entry : this.arpQueue.values()) {
				// broadcast the retried ArpEntry
				if (entry.canResend()) {
					for (Iface routerIface : this.interfaces.values()) {
						sendPacket(entry.getArpRequest(), routerIface);
					}
					entry.incrementRetries();
				} else {
					// clear the queue and send destination unreachable
					while (!entry.isEmpty()) {
						ArpQueueEntry.EthernetQueueEntry packetEntry = entry.poll();
						Iface inIface = packetEntry.getInIface();
						IPv4 ipPacket = (IPv4) packetEntry.getPacket().getPayload();
						Ethernet icmpEtherPkt = getICMPPacket((byte) 3, (byte) 1, inIface, ipPacket,
								packetEntry.getSourceMacAddress());
						sendPacket(icmpEtherPkt, inIface);
					}
					// TODO: do we remove the entry from the table?
				}
			}
		}
	}

	public void runRIPResponse() {
		while (true) {
			// Run every 10 seconds
			try {
				Thread.sleep(10000);
			} catch (InterruptedException e) {
				break;
			}

			for (Iface routerIface : this.interfaces.values()) {
				Ethernet ether = buildRIPResponse(routerIface, "FF:FF:FF:FF:FF:FF", "224.0.0.9");
				ether.setSourceMACAddress(routerIface.getMacAddress().toBytes());
				sendPacket(ether, routerIface);
			}

			// Clear old route entries
			Iterator<RouteEntry> iterator = routeTable.getRouteEntries().iterator();
			while (iterator.hasNext()) {
				RouteEntry routeEntry = iterator.next();
				if (routeEntry.getDistance() > 0 && routeEntry.getLastUpdate() + 30_000 <= System.currentTimeMillis()) {
					iterator.remove();
				}
			}
		}
	}
}

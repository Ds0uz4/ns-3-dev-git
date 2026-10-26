/*
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <cstdlib>
#include <sstream>

#include "sdn-router-controller.h"

#include "ns3/log.h"
#include "ns3/simulator.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("SdnRouterController");

NS_OBJECT_ENSURE_REGISTERED(SdnRouterController);

TypeId
SdnRouterController::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::SdnRouterController")
            .SetParent<OFSwitch13Controller>()
            .SetGroupName("Openflow")
            .AddConstructor<SdnRouterController>();
    return tid;
}

SdnRouterController::SdnRouterController()
{
    NS_LOG_FUNCTION(this);
}

SdnRouterController::~SdnRouterController()
{
    NS_LOG_FUNCTION(this);
}

void
SdnRouterController::DoDispose()
{
    NS_LOG_FUNCTION(this);
    m_interfaces.clear();
    m_routes.clear();
    m_arpTable.clear();
    m_arpQueue.clear();
    OFSwitch13Controller::DoDispose();
}

void
SdnRouterController::AddInterface(uint32_t port, Ipv4Address ip, Ipv4Mask mask, Mac48Address mac)
{
    NS_LOG_FUNCTION(this << port << ip << mask << mac);
    InterfaceEntry entry;
    entry.port = port;
    entry.ip = ip;
    entry.mask = mask;
    entry.mac = mac;
    m_interfaces.push_back(entry);
}

void
SdnRouterController::AddRoute(Ipv4Address network,
                              Ipv4Mask mask,
                              Ipv4Address nextHop,
                              uint32_t outPort,
                              uint16_t priority)
{
    NS_LOG_FUNCTION(this << network << mask << nextHop << outPort << priority);
    RouteEntry entry;
    entry.network = network;
    entry.mask = mask;
    entry.nextHop = nextHop;
    entry.outPort = outPort;
    entry.priority = priority;
    m_routes.push_back(entry);
}

void
SdnRouterController::AddRoute(Ipv4Address network,
                              Ipv4Mask mask,
                              uint32_t outPort,
                              uint16_t priority)
{
    NS_LOG_FUNCTION(this << network << mask << outPort << priority);
    AddRoute(network, mask, Ipv4Address::GetAny(), outPort, priority);
}

void
SdnRouterController::AddArpEntry(Ipv4Address ip, Mac48Address mac)
{
    NS_LOG_FUNCTION(this << ip << mac);
    m_arpTable[ip] = mac;
}

void
SdnRouterController::HandshakeSuccessful(Ptr<const RemoteSwitch> swtch)
{
    NS_LOG_FUNCTION(this << swtch);
    if (!swtch)
    {
        return;
    }

    uint64_t dpId = swtch->GetDpId();

    // Configure switch to send miss packets to controller with up to 128 bytes buffered
    DpctlExecute(dpId, "set-config miss=128");

    // Table 0 miss entry: send unmatched packets to controller
    DpctlExecute(dpId, "flow-mod cmd=add,table=0,prio=0 apply:output=ctrl:128");

    // Table 0 ARP entry: direct all ARP packets to controller
    DpctlExecute(dpId, "flow-mod cmd=add,table=0,prio=200 eth_type=0x0806 apply:output=ctrl:128");

    // Table 0 L2 Router MAC entries: frames addressed to router MACs transition to Table 1 (L3 stage)
    for (size_t i = 0; i < m_interfaces.size(); i++)
    {
        std::ostringstream cmd;
        cmd << "flow-mod cmd=add,table=0,prio=100 eth_dst=" << m_interfaces[i].mac << " goto:1";
        DpctlExecute(dpId, cmd.str());
    }

    // Table 1 miss entry: unrouted IPv4 packets sent to controller
    DpctlExecute(dpId, "flow-mod cmd=add,table=1,prio=0 apply:output=ctrl:128");

    // Proactively push any preconfigured L3 routes whose next-hop MACs are already resolved
    for (size_t i = 0; i < m_routes.size(); i++)
    {
        const RouteEntry* route = &m_routes[i];
        Ipv4Address nextHopIp = route->nextHop;
        if (nextHopIp != Ipv4Address::GetAny() && nextHopIp != Ipv4Address("0.0.0.0"))
        {
            auto arpIt = m_arpTable.find(nextHopIp);
            if (arpIt != m_arpTable.end())
            {
                Mac48Address nextHopMac = arpIt->second;
                const InterfaceEntry* outIface = nullptr;
                for (size_t j = 0; j < m_interfaces.size(); j++)
                {
                    if (m_interfaces[j].port == route->outPort)
                    {
                        outIface = &m_interfaces[j];
                        break;
                    }
                }
                if (outIface)
                {
                    PushL3Flow(dpId,
                               route->network,
                               route->mask.GetPrefixLength(),
                               outIface->mac,
                               nextHopMac,
                               route->outPort,
                               route->priority);
                }
            }
        }
    }
}

ofl_err
SdnRouterController::HandlePacketIn(struct ofl_msg_packet_in* msg,
                                     Ptr<const RemoteSwitch> swtch,
                                     uint32_t xid)
{
    NS_LOG_FUNCTION(this << swtch << xid);
    if (!msg || !swtch)
    {
        if (msg)
        {
            ofl_msg_free((struct ofl_msg_header*)msg, nullptr);
        }
        return 0;
    }

    // Extract input port from match TLV using explicit pointer dereference
    uint32_t inPort = 0;
    struct ofl_match_tlv* input =
        oxm_match_lookup(OXM_OF_IN_PORT, (struct ofl_match*)msg->match);
    if (input && input->value)
    {
        uint32_t* portPtr = (uint32_t*)input->value;
        inPort = *portPtr;
    }

    if (msg->data != nullptr && msg->data_length >= 14)
    {
        // Parse Ethernet type close to the metal with explicit pointer operations
        uint8_t* rawData = msg->data;
        size_t dataLen = msg->data_length;

        uint16_t ethType = (static_cast<uint16_t>(rawData[12]) << 8) |
                           static_cast<uint16_t>(rawData[13]);

        Ptr<Packet> packet = Create<Packet>(rawData, dataLen);
        EthernetHeader ethHdr;
        packet->RemoveHeader(ethHdr);

        if (ethType == 0x0806)
        {
            HandleArpPacket(packet, inPort, swtch, xid);
        }
        else if (ethType == 0x0800)
        {
            HandleIpv4Packet(packet, inPort, swtch, xid);
        }
        else
        {
            NS_LOG_DEBUG("Unhandled EtherType: 0x" << std::hex << ethType << std::dec);
        }
    }

    // Handlers must free received message
    ofl_msg_free((struct ofl_msg_header*)msg, nullptr);
    return 0;
}

void
SdnRouterController::HandleArpPacket(Ptr<Packet> packet,
                                     uint32_t inPort,
                                     Ptr<const RemoteSwitch> swtch,
                                     uint32_t xid)
{
    NS_LOG_FUNCTION(this << packet << inPort << swtch << xid);

    ArpHeader arpHdr;
    packet->RemoveHeader(arpHdr);

    Ipv4Address senderIp = arpHdr.GetSourceIpv4Address();
    Address senderHwAddr = arpHdr.GetSourceHardwareAddress();
    Mac48Address senderMac = Mac48Address::ConvertFrom(senderHwAddr);
    Ipv4Address targetIp = arpHdr.GetDestinationIpv4Address();

    // Learn sender IP to MAC in ARP cache
    m_arpTable[senderIp] = senderMac;

    // Check if any packet was queued waiting for this IP's MAC resolution
    auto qIt = m_arpQueue.find(senderIp);
    if (qIt != m_arpQueue.end())
    {
        Ptr<Packet> queuedPkt = qIt->second;
        m_arpQueue.erase(qIt);
        // Process the queued IPv4 packet now that MAC is known
        HandleIpv4Packet(queuedPkt, inPort, swtch, xid);
    }

    if (arpHdr.IsRequest())
    {
        // Find if request is for the router interface or if the router can proxy for targetIp
        const InterfaceEntry* inIface = nullptr;
        for (size_t i = 0; i < m_interfaces.size(); i++)
        {
            if (m_interfaces[i].port == inPort)
            {
                inIface = &m_interfaces[i];
                break;
            }
        }

        if (!inIface)
        {
            return;
        }

        bool shouldReply = false;
        Mac48Address replyMac = inIface->mac;

        if (targetIp == inIface->ip)
        {
            // Direct request for router's interface
            shouldReply = true;
        }
        else
        {
            // Check if targetIp matches any other interface
            for (size_t i = 0; i < m_interfaces.size(); i++)
            {
                if (targetIp == m_interfaces[i].ip)
                {
                    shouldReply = true;
                    break;
                }
            }

            // If not an interface IP, check if targetIp is reachable via routing table (Proxy ARP)
            if (!shouldReply)
            {
                for (size_t i = 0; i < m_routes.size(); i++)
                {
                    if (m_routes[i].mask.IsMatch(targetIp, m_routes[i].network))
                    {
                        shouldReply = true;
                        break;
                    }
                }
            }
        }

        if (shouldReply)
        {
            ArpHeader arpReply;
            arpReply.SetReply(replyMac, targetIp, senderMac, senderIp);

            EthernetHeader ethReply;
            ethReply.SetSource(replyMac);
            ethReply.SetDestination(senderMac);
            ethReply.SetLengthType(0x0806);

            Ptr<Packet> replyPacket = Create<Packet>();
            replyPacket->AddHeader(arpReply);
            replyPacket->AddHeader(ethReply);

            SendPacketOut(swtch, replyPacket, inPort, xid);
        }
    }
}

void
SdnRouterController::HandleIpv4Packet(Ptr<Packet> packet,
                                      uint32_t inPort,
                                      Ptr<const RemoteSwitch> swtch,
                                      uint32_t xid)
{
    NS_LOG_FUNCTION(this << packet << inPort << swtch << xid);

    Ipv4Header ipHdr;
    packet->RemoveHeader(ipHdr);

    if (ipHdr.GetTtl() <= 1)
    {
        // Drop TTL expired packet
        return;
    }

    Ipv4Address dstIp = ipHdr.GetDestination();
    Ipv4Address srcIp = ipHdr.GetSource();
    NS_LOG_INFO("Handling IPv4 packet from " << srcIp << " to " << dstIp);

    // Check if packet is destined for one of our own router interfaces
    for (size_t i = 0; i < m_interfaces.size(); i++)
    {
        if (dstIp == m_interfaces[i].ip)
        {
            // Packet terminated at the router control plane
            return;
        }
    }

    // Longest prefix match against routing table
    const RouteEntry* bestRoute = nullptr;
    uint16_t bestPrefix = 0;
    for (size_t i = 0; i < m_routes.size(); i++)
    {
        if (m_routes[i].mask.IsMatch(dstIp, m_routes[i].network))
        {
            uint16_t prefixLen = m_routes[i].mask.GetPrefixLength();
            if (bestRoute == nullptr || prefixLen > bestPrefix)
            {
                bestRoute = &m_routes[i];
                bestPrefix = prefixLen;
            }
        }
    }

    if (!bestRoute)
    {
        // No route to destination, drop
        return;
    }

    // Find outgoing router interface
    const InterfaceEntry* outIface = nullptr;
    for (size_t i = 0; i < m_interfaces.size(); i++)
    {
        if (m_interfaces[i].port == bestRoute->outPort)
        {
            outIface = &m_interfaces[i];
            break;
        }
    }

    if (!outIface)
    {
        return;
    }

    // Determine next-hop IP
    Ipv4Address nextHopIp = bestRoute->nextHop;
    bool isDirectSubnet = false;
    if (nextHopIp == Ipv4Address::GetAny() || nextHopIp == Ipv4Address("0.0.0.0"))
    {
        // Direct subnet: next hop is the destination host itself
        nextHopIp = dstIp;
        isDirectSubnet = true;
    }

    // Check ARP table for next-hop MAC
    Mac48Address nextHopMac;
    bool arpFound = false;
    auto arpIt = m_arpTable.find(nextHopIp);
    if (arpIt != m_arpTable.end())
    {
        nextHopMac = arpIt->second;
        arpFound = true;
    }

    uint64_t dpId = swtch->GetDpId();

    if (arpFound)
    {
        // Next-hop MAC is known. Push L3 routing rule to Table 1
        if (isDirectSubnet)
        {
            // Push host-specific /32 rule for directly connected host
            PushL3Flow(dpId, dstIp, 32, outIface->mac, nextHopMac, bestRoute->outPort, bestRoute->priority + 1);
        }
        else
        {
            // Push network prefix rule for next-hop gateway
            PushL3Flow(dpId, bestRoute->network, bestPrefix, outIface->mac, nextHopMac, bestRoute->outPort, bestRoute->priority);
        }

        // Forward the current packet: decrement TTL, update Ethernet MACs, and send
        ipHdr.SetTtl(ipHdr.GetTtl() - 1);

        EthernetHeader ethHdr;
        ethHdr.SetSource(outIface->mac);
        ethHdr.SetDestination(nextHopMac);
        ethHdr.SetLengthType(0x0800);

        packet->AddHeader(ipHdr);
        packet->AddHeader(ethHdr);

        SendPacketOut(swtch, packet, bestRoute->outPort, xid);
    }
    else
    {
        // Next-hop MAC is unknown. Queue packet and send ARP request
        packet->AddHeader(ipHdr);
        m_arpQueue[nextHopIp] = packet;

        SendArpRequest(swtch, outIface, nextHopIp, xid);
    }
}

void
SdnRouterController::PushL3Flow(uint64_t dpId,
                                Ipv4Address dstNet,
                                uint16_t prefixLen,
                                Mac48Address srcMac,
                                Mac48Address dstMac,
                                uint32_t outPort,
                                uint16_t priority)
{
    NS_LOG_FUNCTION(this << dpId << dstNet << prefixLen << srcMac << dstMac << outPort << priority);

    std::ostringstream cmd;
    cmd << "flow-mod cmd=add,table=1,prio=" << priority
        << " eth_type=0x0800,ip_dst=" << dstNet;
    if (prefixLen < 32)
    {
        cmd << "/" << prefixLen;
    }
    cmd << " apply:nw_dec,set_field=eth_src:" << srcMac
        << ",set_field=eth_dst:" << dstMac
        << ",output:" << outPort;

    DpctlExecute(dpId, cmd.str());
}

void
SdnRouterController::SendPacketOut(Ptr<const RemoteSwitch> swtch,
                                   Ptr<Packet> packet,
                                   uint32_t outPort,
                                   uint32_t xid)
{
    NS_LOG_FUNCTION(this << swtch << packet << outPort << xid);
    if (!swtch || !packet)
    {
        return;
    }

    uint32_t pktSize = packet->GetSize();
    uint8_t* buffer = (uint8_t*)malloc(pktSize);
    if (!buffer)
    {
        return;
    }
    packet->CopyData(buffer, pktSize);

    struct ofl_msg_packet_out reply;
    reply.header.type = OFPT_PACKET_OUT;
    reply.buffer_id = OFP_NO_BUFFER;
    reply.in_port = OFPP_CONTROLLER;
    reply.data_length = pktSize;
    reply.data = buffer;

    struct ofl_action_output* a =
        (struct ofl_action_output*)xmalloc(sizeof(struct ofl_action_output));
    a->header.type = OFPAT_OUTPUT;
    a->port = outPort;
    a->max_len = 0;

    reply.actions_num = 1;
    reply.actions = (struct ofl_action_header**)&a;

    SendToSwitch(swtch, (struct ofl_msg_header*)&reply, xid);

    free(a);
    free(buffer);
}

void
SdnRouterController::SendArpRequest(Ptr<const RemoteSwitch> swtch,
                                    const InterfaceEntry* outIface,
                                    Ipv4Address targetIp,
                                    uint32_t xid)
{
    NS_LOG_FUNCTION(this << swtch << outIface << targetIp << xid);
    if (!swtch || !outIface)
    {
        return;
    }

    ArpHeader arpReq;
    arpReq.SetRequest(outIface->mac, outIface->ip, Mac48Address::GetBroadcast(), targetIp);

    EthernetHeader ethHdr;
    ethHdr.SetSource(outIface->mac);
    ethHdr.SetDestination(Mac48Address::GetBroadcast());
    ethHdr.SetLengthType(0x0806);

    Ptr<Packet> arpPacket = Create<Packet>();
    arpPacket->AddHeader(arpReq);
    arpPacket->AddHeader(ethHdr);

    SendPacketOut(swtch, arpPacket, outIface->port, xid);
}

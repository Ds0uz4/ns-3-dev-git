/*
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef SDN_ROUTER_CONTROLLER_H
#define SDN_ROUTER_CONTROLLER_H

#include "sdn-router-switch.h"

#include "ns3/address.h"
#include "ns3/arp-header.h"
#include "ns3/ethernet-header.h"
#include "ns3/ipv4-address.h"
#include "ns3/ipv4-header.h"
#include "ns3/mac48-address.h"
#include "ns3/ofswitch13-controller.h"
#include "ns3/packet.h"
#include "ns3/ptr.h"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

// Requested project convention: pull the ns3 namespace in globally so the
// declarations below carry no ns3:: prefixes.
using namespace ns3;

/**
 * @ingroup openflow
 *
 * @brief Control Plane application for an SDN router in the ns-3 network simulator.
 *
 * This class implements the Control Plane (the "Brain") of an SDN router.
 * It manages an OpenFlow 1.3 data plane (SdnRouterSwitch), handles raw packet-in
 * events, acts as an ARP proxy for router interfaces and routable subnets, and
 * pushes Layer 3 routing rules into the OpenFlow pipeline tables.
 */
class SdnRouterController : public OFSwitch13Controller
{
  public:
    /**
     * @brief Representation of a router network interface.
     */
    struct InterfaceEntry
    {
        uint32_t port;    //!< Switch OpenFlow port number.
        Ipv4Address ip;   //!< IPv4 address assigned to this interface.
        Ipv4Mask mask;    //!< Subnet mask of this interface.
        Mac48Address mac; //!< Hardware MAC address of this interface.
    };

    /**
     * @brief Representation of a routing table entry.
     */
    struct RouteEntry
    {
        Ipv4Address network; //!< Destination network address.
        Ipv4Mask mask;       //!< Destination subnet mask.
        Ipv4Address nextHop; //!< Next-hop IPv4 gateway address (0.0.0.0 if direct).
        uint32_t outPort;    //!< Outgoing switch port number.
        uint16_t priority;   //!< Flow entry priority in Table 1.
    };

    /**
     * Register this type.
     *
     * @return The object TypeId.
     */
    static TypeId GetTypeId();

    SdnRouterController();           //!< Default constructor.
    ~SdnRouterController() override; //!< Destructor.

    /**
     * Add a router network interface.
     *
     * @param port The OpenFlow port number on the switch.
     * @param ip The IPv4 address of this interface.
     * @param mask The subnet mask for this interface.
     * @param mac The MAC address of this interface.
     */
    void AddInterface(uint32_t port, Ipv4Address ip, Ipv4Mask mask, Mac48Address mac);

    /**
     * Add a static Layer 3 route.
     *
     * @param network Destination network IP address.
     * @param mask Destination subnet mask.
     * @param nextHop Next-hop IPv4 address (0.0.0.0 for directly connected subnet).
     * @param outPort Outgoing switch port number.
     * @param priority Priority of the flow rule in Table 1 (higher takes precedence).
     */
    void AddRoute(Ipv4Address network,
                  Ipv4Mask mask,
                  Ipv4Address nextHop,
                  uint32_t outPort,
                  uint16_t priority = 100);

    /**
     * Add a direct Layer 3 route for a directly connected subnet.
     *
     * @param network Destination network IP address.
     * @param mask Destination subnet mask.
     * @param outPort Outgoing switch port number.
     * @param priority Priority of the flow rule in Table 1.
     */
    void AddRoute(Ipv4Address network,
                  Ipv4Mask mask,
                  uint32_t outPort,
                  uint16_t priority = 100);

    /**
     * Statically populate or override an entry in the controller ARP cache.
     *
     * @param ip The IPv4 address to map.
     * @param mac The resolved MAC hardware address.
     */
    void AddArpEntry(Ipv4Address ip, Mac48Address mac);

    /**
     * Handle packet-in messages received from the connected OpenFlow switch.
     *
     * Parses the incoming packet, answers ARP requests as an ARP proxy,
     * routes IPv4 packets, and pushes reactive flow entries to the switch pipeline.
     *
     * @param msg The OpenFlow packet-in message pointer.
     * @param swtch Metadata of the remote switch sending the message.
     * @param xid Transaction ID of the message.
     * @return 0 on success, or an OpenFlow error code.
     */
    ofl_err HandlePacketIn(struct ofl_msg_packet_in* msg,
                           Ptr<const RemoteSwitch> swtch,
                           uint32_t xid) override;

  protected:
    /**
     * Dispose of application resources.
     */
    void DoDispose() override;

    /**
     * Callback invoked after OpenFlow handshake completes with a switch.
     * Installs baseline Table 0 L2 rules and Table 1 L3 rules.
     *
     * @param swtch Pointer to the remote switch that completed handshake.
     */
    void HandshakeSuccessful(Ptr<const RemoteSwitch> swtch) override;

    /**
     * Process an incoming ARP packet.
     *
     * @param packet The ns-3 packet containing the ARP frame.
     * @param inPort Switch port where the packet was received.
     * @param swtch Remote switch that sent the packet-in.
     * @param xid OpenFlow transaction ID.
     */
    void HandleArpPacket(Ptr<Packet> packet,
                         uint32_t inPort,
                         Ptr<const RemoteSwitch> swtch,
                         uint32_t xid);

    /**
     * Process an incoming IPv4 packet.
     *
     * @param packet The ns-3 packet containing the IPv4 frame.
     * @param inPort Switch port where the packet was received.
     * @param swtch Remote switch that sent the packet-in.
     * @param xid OpenFlow transaction ID.
     */
    void HandleIpv4Packet(Ptr<Packet> packet,
                          uint32_t inPort,
                          Ptr<const RemoteSwitch> swtch,
                          uint32_t xid);

    /**
     * Push a Layer 3 flow entry to Table 1 of the switch.
     *
     * @param dpId Switch OpenFlow datapath ID.
     * @param dstNet Destination IPv4 network address.
     * @param prefixLen Prefix length (CIDR mask).
     * @param srcMac Router source MAC address to set.
     * @param dstMac Next-hop destination MAC address to set.
     * @param outPort Switch port to output the packet.
     * @param priority Flow rule priority.
     */
    void PushL3Flow(uint64_t dpId,
                    Ipv4Address dstNet,
                    uint16_t prefixLen,
                    Mac48Address srcMac,
                    Mac48Address dstMac,
                    uint32_t outPort,
                    uint16_t priority);

    /**
     * Send a packet out of a switch port via an OpenFlow packet-out message.
     *
     * @param swtch Remote switch to transmit the packet.
     * @param packet The packet data to send.
     * @param outPort Switch port where the packet must exit.
     * @param xid OpenFlow transaction ID.
     */
    void SendPacketOut(Ptr<const RemoteSwitch> swtch,
                       Ptr<Packet> packet,
                       uint32_t outPort,
                       uint32_t xid);

    /**
     * Send an ARP request to resolve a destination IP address.
     *
     * @param swtch Remote switch to transmit the ARP request.
     * @param outIface Router interface transmitting the request.
     * @param targetIp The IPv4 address being resolved.
     * @param xid OpenFlow transaction ID.
     */
    void SendArpRequest(Ptr<const RemoteSwitch> swtch,
                        const InterfaceEntry* outIface,
                        Ipv4Address targetIp,
                        uint32_t xid);

  private:
    std::vector<InterfaceEntry> m_interfaces;       //!< Configured router interfaces.
    std::vector<RouteEntry> m_routes;               //!< Configured Layer 3 routes.
    std::map<Ipv4Address, Mac48Address> m_arpTable; //!< ARP resolution cache (IP -> MAC).
    std::map<Ipv4Address, Ptr<Packet>> m_arpQueue;  //!< Packets queued waiting for ARP reply.
};

#endif /* SDN_ROUTER_CONTROLLER_H */

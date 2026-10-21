/*
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef SDN_ROUTER_SWITCH_H
#define SDN_ROUTER_SWITCH_H

#include "ns3/ipv4-address.h"
#include "ns3/net-device-container.h"
#include "ns3/net-device.h"
#include "ns3/node.h"
#include "ns3/nstime.h"
#include "ns3/object.h"
#include "ns3/ofswitch13-device.h"
#include "ns3/ofswitch13-port.h"
#include "ns3/ptr.h"

#include <cstdint>
#include <vector>

// Requested project convention: pull the ns3 namespace in globally so the
// declarations below carry no ns3:: prefixes. This leaks into every includer;
// drop it if this header is ever upstreamed into src/.
using namespace ns3;

/**
 * @ingroup openflow
 *
 * @brief OpenFlow 1.3 switch node prepared to act as an L3 SDN router data plane.
 *
 * This class is the "Brawn" half of an SDN router. It wraps one OFSwitch13Device
 * (the BOFUSS-based OpenFlow 1.3 datapath from the OFSwitch13 module), aggregates
 * it to a Node, attaches physical ports, and opens the OpenFlow control channel
 * (TCP) toward a controller address. It installs no flow entries and handles no
 * packet-in messages: all forwarding state arrives later over the control channel.
 *
 * Pipeline plan, fixed by this class and expected by the future controller:
 *
 *   - Table 0 (TABLE_L2_MAC): Layer 2 stage. Match on in_port / eth_src / eth_dst.
 *     Frames addressed to the router MAC get "goto-table 1"; the table-miss entry
 *     is also expected to be installed by the controller.
 *   - Table 1 (TABLE_L3_IPV4): Layer 3 stage. Match on eth_type=0x0800 and
 *     ipv4_dst (longest prefix via flow priority). Instructions apply-actions:
 *     dec_nw_ttl, set_field eth_src, set_field eth_dst, output:port.
 *
 * OpenFlow 1.3 has no notion of table roles in the datapath itself; the roles are
 * conventions realised by the flow entries the controller installs. This class
 * only guarantees that at least two tables exist and exposes the table ids.
 *
 * Attributes must be set before Install(); they are applied when the underlying
 * OFSwitch13Device is created.
 */
class SdnRouterSwitch : public Object
{
  public:
    /// Pipeline table ids reserved by this router design.
    enum PipelineTable : uint8_t
    {
        TABLE_L2_MAC = 0,  //!< Layer 2 MAC stage.
        TABLE_L3_IPV4 = 1, //!< Layer 3 IPv4 routing stage.
    };

    /// Minimum number of pipeline tables this switch will configure.
    static constexpr uint32_t MIN_PIPELINE_TABLES = 2;

    /**
     * Register this type.
     * @return The object TypeId.
     */
    static TypeId GetTypeId();

    SdnRouterSwitch();           //!< Default constructor.
    ~SdnRouterSwitch() override; //!< Destructor.

    /**
     * Create the OpenFlow 1.3 device and aggregate it to the given node.
     *
     * Installs the Internet stack on the node if it has none (the control channel
     * is a TCP socket on that stack) and enables ns-3 checksums, which OFSwitch13
     * requires.
     *
     * @param node The node that becomes the switch. Must not already host an
     *             OFSwitch13Device.
     * @return The created OpenFlow device.
     */
    Ptr<OFSwitch13Device> Install(Ptr<Node> node);

    /**
     * Attach one physical port to the switch.
     *
     * The device must carry Ethernet framing; OFSwitch13 accepts CsmaNetDevice
     * (physical ports) and VirtualNetDevice (logical ports). OpenFlow port
     * numbers are assigned in call order starting at 1.
     *
     * @param device The NetDevice to attach.
     * @return The OpenFlow port number assigned to the device.
     */
    uint32_t AddPort(Ptr<NetDevice> device);

    /**
     * Attach several physical ports, in container order.
     *
     * @param devices The NetDevices to attach.
     * @return The OpenFlow port numbers assigned, in the same order.
     */
    std::vector<uint32_t> AddPorts(const NetDeviceContainer& devices);

    /**
     * Schedule the TCP connection from the switch to the controller.
     *
     * Uses the ControllerAddress and ControllerPort attributes. The switch node
     * must already have an IP route to that address (see the notes in the
     * implementation about loopback and external controllers). Call at most once.
     *
     * @param delay Simulation time from now at which the connection starts.
     */
    void ConnectController(Time delay = Seconds(0));

    /**
     * Override the controller endpoint after construction and before
     * ConnectController().
     *
     * @param address The controller IPv4 address.
     * @param port The controller TCP port.
     */
    void SetController(Ipv4Address address, uint16_t port);

    /** @return The node hosting the switch, or null before Install(). */
    Ptr<Node> GetNode() const;

    /** @return The OpenFlow device, or null before Install(). */
    Ptr<OFSwitch13Device> GetDevice() const;

    /** @return The OpenFlow datapath id. */
    uint64_t GetDatapathId() const;

    /** @return The number of attached switch ports. */
    uint32_t GetNPorts() const;

    /** @return The number of configured pipeline tables. */
    uint32_t GetNPipelineTables() const;

    /**
     * @param tableId The pipeline table id.
     * @return The number of flow entries currently installed in that table.
     */
    uint32_t GetFlowEntries(uint8_t tableId) const;

  protected:
    void DoDispose() override;

  private:
    Ptr<Node> m_node;               //!< Node hosting the switch.
    Ptr<OFSwitch13Device> m_device; //!< OpenFlow 1.3 datapath.
    uint32_t m_nTables;             //!< Pipeline tables (attribute PipelineTables).
    uint32_t m_flowTableSize;       //!< Entries per flow table (attribute FlowTableSize).
    Ipv4Address m_ctrlAddr;         //!< Controller address (attribute ControllerAddress).
    uint16_t m_ctrlPort;            //!< Controller TCP port (attribute ControllerPort).
    bool m_connectScheduled;        //!< True once ConnectController() has been called.
};

#endif /* SDN_ROUTER_SWITCH_H */

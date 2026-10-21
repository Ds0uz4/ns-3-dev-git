/*
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "sdn-router-switch.h"

#include "ns3/abort.h"
#include "ns3/boolean.h"
#include "ns3/global-value.h"
#include "ns3/inet-socket-address.h"
#include "ns3/internet-stack-helper.h"
#include "ns3/ipv4.h"
#include "ns3/log.h"
#include "ns3/object-factory.h"
#include "ns3/simulator.h"
#include "ns3/uinteger.h"

NS_LOG_COMPONENT_DEFINE("SdnRouterSwitch");

NS_OBJECT_ENSURE_REGISTERED(SdnRouterSwitch);

namespace
{
/// Default OpenFlow controller TCP port (IANA-assigned for OpenFlow).
constexpr uint16_t DEFAULT_OF_PORT = 6653;
} // namespace

TypeId
SdnRouterSwitch::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::SdnRouterSwitch")
            .SetParent<Object>()
            .SetGroupName("Openflow")
            .AddConstructor<SdnRouterSwitch>()
            .AddAttribute("PipelineTables",
                          "Number of OpenFlow pipeline tables. Table 0 is the L2 MAC stage and "
                          "table 1 the L3 IPv4 stage, so the minimum is 2.",
                          UintegerValue(MIN_PIPELINE_TABLES),
                          MakeUintegerAccessor(&SdnRouterSwitch::m_nTables),
                          MakeUintegerChecker<uint32_t>(MIN_PIPELINE_TABLES, 255))
            .AddAttribute("FlowTableSize",
                          "Maximum number of entries in each flow table.",
                          UintegerValue(8192),
                          MakeUintegerAccessor(&SdnRouterSwitch::m_flowTableSize),
                          MakeUintegerChecker<uint32_t>(1))
            .AddAttribute("ControllerAddress",
                          "IPv4 address of the OpenFlow controller the switch connects to.",
                          Ipv4AddressValue(Ipv4Address::GetLoopback()),
                          MakeIpv4AddressAccessor(&SdnRouterSwitch::m_ctrlAddr),
                          MakeIpv4AddressChecker())
            .AddAttribute("ControllerPort",
                          "TCP port of the OpenFlow controller.",
                          UintegerValue(DEFAULT_OF_PORT),
                          MakeUintegerAccessor(&SdnRouterSwitch::m_ctrlPort),
                          MakeUintegerChecker<uint16_t>());
    return tid;
}

SdnRouterSwitch::SdnRouterSwitch()
    : m_nTables(MIN_PIPELINE_TABLES),
      m_flowTableSize(8192),
      m_ctrlAddr(Ipv4Address::GetLoopback()),
      m_ctrlPort(DEFAULT_OF_PORT),
      m_connectScheduled(false)
{
    NS_LOG_FUNCTION(this);
}

SdnRouterSwitch::~SdnRouterSwitch()
{
    NS_LOG_FUNCTION(this);
}

void
SdnRouterSwitch::DoDispose()
{
    NS_LOG_FUNCTION(this);
    m_device = nullptr;
    m_node = nullptr;
    Object::DoDispose();
}

Ptr<OFSwitch13Device>
SdnRouterSwitch::Install(Ptr<Node> node)
{
    NS_LOG_FUNCTION(this << node);
    NS_ABORT_MSG_IF(!node, "Cannot install an SDN router switch on a null node");
    NS_ABORT_MSG_IF(m_device, "SdnRouterSwitch is already installed on a node");
    NS_ABORT_MSG_IF(node->GetObject<OFSwitch13Device>(), "Node already hosts an OFSwitch13Device");

    // The control channel is a TCP socket opened on the switch node, so the
    // node needs an IP stack even though the data plane is pure Ethernet.
    if (!node->GetObject<Ipv4>())
    {
        InternetStackHelper internet;
        internet.Install(node);
    }

    // OFSwitch13 parses real OpenFlow messages off the wire and requires
    // valid checksums on the control path.
    GlobalValue::Bind("ChecksumEnabled", BooleanValue(true));

    // PipelineTables is construct-only on the device, so the pipeline shape
    // (table 0 = L2, table 1 = L3, spares beyond) is fixed here.
    ObjectFactory factory;
    factory.SetTypeId("ns3::OFSwitch13Device");
    factory.Set("PipelineTables", UintegerValue(m_nTables));
    factory.Set("FlowTableSize", UintegerValue(m_flowTableSize));
    m_device = factory.Create<OFSwitch13Device>();

    node->AggregateObject(m_device);
    m_node = node;

    NS_LOG_INFO("Switch node " << node->GetId() << " dpid " << m_device->GetDatapathId() << " with "
                               << m_nTables << " pipeline tables");
    return m_device;
}

uint32_t
SdnRouterSwitch::AddPort(Ptr<NetDevice> device)
{
    NS_LOG_FUNCTION(this << device);
    NS_ABORT_MSG_IF(!m_device, "Call Install() before AddPort()");
    NS_ABORT_MSG_IF(!device, "Cannot attach a null NetDevice");

    // The datapath takes over the device's receive callback in promiscuous
    // mode and forwards every L2 frame into the pipeline.
    Ptr<OFSwitch13Port> port = m_device->AddSwitchPort(device);
    NS_LOG_INFO("Port " << port->GetPortNo() << " bound to device " << device->GetIfIndex());
    return port->GetPortNo();
}

std::vector<uint32_t>
SdnRouterSwitch::AddPorts(const NetDeviceContainer& devices)
{
    NS_LOG_FUNCTION(this);
    std::vector<uint32_t> portNumbers;
    portNumbers.reserve(devices.GetN());
    for (auto it = devices.Begin(); it != devices.End(); ++it)
    {
        portNumbers.push_back(AddPort(*it));
    }
    return portNumbers;
}

void
SdnRouterSwitch::SetController(Ipv4Address address, uint16_t port)
{
    NS_LOG_FUNCTION(this << address << port);
    NS_ABORT_MSG_IF(m_connectScheduled, "Controller already connected; cannot change endpoint");
    m_ctrlAddr = address;
    m_ctrlPort = port;
}

void
SdnRouterSwitch::ConnectController(Time delay)
{
    NS_LOG_FUNCTION(this << delay);
    NS_ABORT_MSG_IF(!m_device, "Call Install() before ConnectController()");
    NS_ABORT_MSG_IF(m_connectScheduled, "ConnectController() may only be called once");
    NS_ABORT_MSG_IF(m_device->GetNSwitchPorts() == 0,
                    "Attach at least one port before connecting the controller");

    // StartControllerConnection opens an ns-3 TCP socket on the switch node and
    // connects to the endpoint; the OpenFlow HELLO / feature negotiation then
    // proceeds with whatever answers on the other side.
    //
    // Reachability notes:
    //  - A loopback address (the default, 127.0.0.1) terminates on this same
    //    node's stack, so it only works for a controller application installed
    //    on the switch node itself.
    //  - For a controller on another simulated node, give the switch node an
    //    IP interface on a control channel and set ControllerAddress to the
    //    controller's address on it.
    //  - For a controller process outside the simulator, run in real-time mode
    //    and use OFSwitch13ExternalHelper::InstallExternalController(), which
    //    bridges a controller node to the host over a TapBridge.
    m_connectScheduled = true;
    Address ctrl = InetSocketAddress(m_ctrlAddr, m_ctrlPort);
    Simulator::Schedule(delay, &OFSwitch13Device::StartControllerConnection, m_device, ctrl);
}

Ptr<Node>
SdnRouterSwitch::GetNode() const
{
    return m_node;
}

Ptr<OFSwitch13Device>
SdnRouterSwitch::GetDevice() const
{
    return m_device;
}

uint64_t
SdnRouterSwitch::GetDatapathId() const
{
    NS_ABORT_MSG_IF(!m_device, "Call Install() first");
    return m_device->GetDatapathId();
}

uint32_t
SdnRouterSwitch::GetNPorts() const
{
    return m_device ? m_device->GetNSwitchPorts() : 0;
}

uint32_t
SdnRouterSwitch::GetNPipelineTables() const
{
    return m_device ? m_device->GetNPipelineTables() : 0;
}

uint32_t
SdnRouterSwitch::GetFlowEntries(uint8_t tableId) const
{
    NS_ABORT_MSG_IF(!m_device, "Call Install() first");
    return m_device->GetFlowTableEntries(tableId);
}

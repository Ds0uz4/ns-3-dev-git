/*
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "ns3/sdn-router-controller.h"
#include "ns3/sdn-router-switch.h"

#include "ns3/arp-header.h"
#include "ns3/boolean.h"
#include "ns3/ethernet-header.h"
#include "ns3/ipv4-address.h"
#include "ns3/ipv4-header.h"
#include "ns3/mac48-address.h"
#include "ns3/packet.h"
#include "ns3/simulator.h"
#include "ns3/test.h"
#include "ns3/uinteger.h"

using namespace ns3;

/**
 * @defgroup sdn-router-tests Tests for SDN Router module
 * @ingroup tests
 */

/**
 * @ingroup sdn-router-tests
 *
 * @brief Test case for SdnRouterSwitch data plane configuration.
 */
class SdnRouterSwitchConfigTestCase : public TestCase
{
  public:
    SdnRouterSwitchConfigTestCase();
    ~SdnRouterSwitchConfigTestCase() override;

  private:
    void DoRun() override;
    void DoTeardown() override;
};

SdnRouterSwitchConfigTestCase::SdnRouterSwitchConfigTestCase()
    : TestCase("Verify SdnRouterSwitch TypeId, attributes, and pipeline constants")
{
}

SdnRouterSwitchConfigTestCase::~SdnRouterSwitchConfigTestCase()
{
}

void
SdnRouterSwitchConfigTestCase::DoTeardown()
{
    Simulator::Destroy();
}

void
SdnRouterSwitchConfigTestCase::DoRun()
{
    // Test pipeline table enum constants
    NS_TEST_ASSERT_MSG_EQ(SdnRouterSwitch::TABLE_L2_MAC, 0, "TABLE_L2_MAC must be 0");
    NS_TEST_ASSERT_MSG_EQ(SdnRouterSwitch::TABLE_L3_IPV4, 1, "TABLE_L3_IPV4 must be 1");
    NS_TEST_ASSERT_MSG_EQ(SdnRouterSwitch::MIN_PIPELINE_TABLES, 2, "MIN_PIPELINE_TABLES must be 2");

    // Create switch object and verify TypeId
    Ptr<SdnRouterSwitch> swtch = CreateObject<SdnRouterSwitch>();
    NS_TEST_ASSERT_MSG_NE(swtch, nullptr, "Failed to instantiate SdnRouterSwitch");
    NS_TEST_ASSERT_MSG_EQ(swtch->GetInstanceTypeId().GetName(),
                          "ns3::SdnRouterSwitch",
                          "Incorrect TypeId for SdnRouterSwitch");

    // Verify default controller endpoint configuration
    swtch->SetController(Ipv4Address("127.0.0.1"), 6653);
    NS_TEST_ASSERT_MSG_EQ(swtch->GetNPorts(), 0, "Initial port count must be 0");
    NS_TEST_ASSERT_MSG_EQ(swtch->GetNPipelineTables(), 0, "Pipeline tables uninstalled should be 0");
}

/**
 * @ingroup sdn-router-tests
 *
 * @brief Test case for SdnRouterController control plane configuration.
 */
class SdnRouterControllerConfigTestCase : public TestCase
{
  public:
    SdnRouterControllerConfigTestCase();
    ~SdnRouterControllerConfigTestCase() override;

  private:
    void DoRun() override;
    void DoTeardown() override;
};

SdnRouterControllerConfigTestCase::SdnRouterControllerConfigTestCase()
    : TestCase("Verify SdnRouterController interface, route, and ARP table management")
{
}

SdnRouterControllerConfigTestCase::~SdnRouterControllerConfigTestCase()
{
}

void
SdnRouterControllerConfigTestCase::DoTeardown()
{
    Simulator::Destroy();
}

void
SdnRouterControllerConfigTestCase::DoRun()
{
    // Create controller application and verify TypeId
    Ptr<SdnRouterController> controller = CreateObject<SdnRouterController>();
    NS_TEST_ASSERT_MSG_NE(controller, nullptr, "Failed to instantiate SdnRouterController");
    NS_TEST_ASSERT_MSG_EQ(controller->GetInstanceTypeId().GetName(),
                          "ns3::SdnRouterController",
                          "Incorrect TypeId for SdnRouterController");

    // Add router interfaces
    controller->AddInterface(1,
                             Ipv4Address("10.0.1.1"),
                             Ipv4Mask("255.255.255.0"),
                             Mac48Address("00:00:00:00:00:01"));
    controller->AddInterface(2,
                             Ipv4Address("10.0.2.1"),
                             Ipv4Mask("255.255.255.0"),
                             Mac48Address("00:00:00:00:00:02"));

    // Add direct subnet routes
    controller->AddRoute(Ipv4Address("10.0.1.0"), Ipv4Mask("255.255.255.0"), 1, 100);
    controller->AddRoute(Ipv4Address("10.0.2.0"), Ipv4Mask("255.255.255.0"), 2, 100);

    // Add indirect route via gateway
    controller->AddRoute(Ipv4Address("10.0.3.0"),
                         Ipv4Mask("255.255.255.0"),
                         Ipv4Address("10.0.2.254"),
                         2,
                         100);

    // Statically populate ARP cache
    controller->AddArpEntry(Ipv4Address("10.0.2.254"), Mac48Address("00:00:00:00:02:fe"));
    controller->AddArpEntry(Ipv4Address("10.0.1.10"), Mac48Address("00:00:00:00:01:10"));
}

/**
 * @ingroup sdn-router-tests
 *
 * @brief Test case for ARP packet header construction and verification.
 */
class SdnRouterArpPacketTestCase : public TestCase
{
  public:
    SdnRouterArpPacketTestCase();
    ~SdnRouterArpPacketTestCase() override;

  private:
    void DoRun() override;
    void DoTeardown() override;
};

SdnRouterArpPacketTestCase::SdnRouterArpPacketTestCase()
    : TestCase("Verify ARP packet creation and header decoding for SDN router ARP proxy")
{
}

SdnRouterArpPacketTestCase::~SdnRouterArpPacketTestCase()
{
}

void
SdnRouterArpPacketTestCase::DoTeardown()
{
    Simulator::Destroy();
}

void
SdnRouterArpPacketTestCase::DoRun()
{
    Mac48Address hostMac("00:00:00:00:00:10");
    Ipv4Address hostIp("10.0.1.10");
    Ipv4Address routerIp("10.0.1.1");
    Mac48Address routerMac("00:00:00:00:00:01");

    // Construct ARP Request frame as received by the controller
    ArpHeader arpReq;
    arpReq.SetRequest(hostMac, hostIp, Mac48Address::GetBroadcast(), routerIp);

    EthernetHeader ethHdr;
    ethHdr.SetSource(hostMac);
    ethHdr.SetDestination(Mac48Address::GetBroadcast());
    ethHdr.SetLengthType(0x0806);

    Ptr<Packet> packet = Create<Packet>();
    packet->AddHeader(arpReq);
    packet->AddHeader(ethHdr);

    NS_TEST_ASSERT_MSG_GT(packet->GetSize(), 0, "Packet size must be greater than 0");

    // Inspect Ethernet header
    EthernetHeader rxEth;
    packet->RemoveHeader(rxEth);
    NS_TEST_ASSERT_MSG_EQ(rxEth.GetLengthType(), 0x0806, "EtherType must be ARP (0x0806)");
    NS_TEST_ASSERT_MSG_EQ(rxEth.GetSource(), hostMac, "Source MAC must match sender");
    NS_TEST_ASSERT_MSG_EQ(rxEth.GetDestination(),
                          Mac48Address::GetBroadcast(),
                          "Destination MAC must be broadcast");

    // Inspect ARP header
    ArpHeader rxArp;
    packet->RemoveHeader(rxArp);
    NS_TEST_ASSERT_MSG_EQ(rxArp.IsRequest(), true, "ARP header must indicate request");
    NS_TEST_ASSERT_MSG_EQ(rxArp.GetSourceIpv4Address(), hostIp, "Sender IP must match");
    NS_TEST_ASSERT_MSG_EQ(rxArp.GetDestinationIpv4Address(), routerIp, "Target IP must match");

    // Construct ARP Reply frame as sent by the ARP proxy
    ArpHeader arpReply;
    arpReply.SetReply(routerMac, routerIp, hostMac, hostIp);

    EthernetHeader ethReply;
    ethReply.SetSource(routerMac);
    ethReply.SetDestination(hostMac);
    ethReply.SetLengthType(0x0806);

    Ptr<Packet> replyPkt = Create<Packet>();
    replyPkt->AddHeader(arpReply);
    replyPkt->AddHeader(ethReply);

    EthernetHeader rxReplyEth;
    replyPkt->RemoveHeader(rxReplyEth);
    NS_TEST_ASSERT_MSG_EQ(rxReplyEth.GetSource(), routerMac, "Reply source MAC must be router MAC");
    NS_TEST_ASSERT_MSG_EQ(rxReplyEth.GetDestination(), hostMac, "Reply destination MAC must be host MAC");

    ArpHeader rxReplyArp;
    replyPkt->RemoveHeader(rxReplyArp);
    NS_TEST_ASSERT_MSG_EQ(rxReplyArp.IsReply(), true, "ARP header must indicate reply");
    NS_TEST_ASSERT_MSG_EQ(rxReplyArp.GetSourceIpv4Address(), routerIp, "Reply sender IP must be router IP");
    NS_TEST_ASSERT_MSG_EQ(rxReplyArp.GetDestinationIpv4Address(), hostIp, "Reply target IP must be host IP");
}

/**
 * @ingroup sdn-router-tests
 *
 * @brief Test case for IPv4 packet routing header manipulation (TTL, MAC rewriting).
 */
class SdnRouterL3PacketTestCase : public TestCase
{
  public:
    SdnRouterL3PacketTestCase();
    ~SdnRouterL3PacketTestCase() override;

  private:
    void DoRun() override;
    void DoTeardown() override;
};

SdnRouterL3PacketTestCase::SdnRouterL3PacketTestCase()
    : TestCase("Verify IPv4 packet TTL decrement and MAC header rewrite for L3 routing")
{
}

SdnRouterL3PacketTestCase::~SdnRouterL3PacketTestCase()
{
}

void
SdnRouterL3PacketTestCase::DoTeardown()
{
    Simulator::Destroy();
}

void
SdnRouterL3PacketTestCase::DoRun()
{
    Mac48Address srcMac("00:00:00:00:00:10");
    Mac48Address routerInMac("00:00:00:00:00:01");
    Mac48Address routerOutMac("00:00:00:00:00:02");
    Mac48Address nextHopMac("00:00:00:00:00:20");

    Ipv4Address srcIp("10.0.1.10");
    Ipv4Address dstIp("10.0.2.20");

    // Construct original packet
    Ipv4Header ipHdr;
    ipHdr.SetSource(srcIp);
    ipHdr.SetDestination(dstIp);
    ipHdr.SetTtl(64);

    EthernetHeader ethHdr;
    ethHdr.SetSource(srcMac);
    ethHdr.SetDestination(routerInMac);
    ethHdr.SetLengthType(0x0800);

    Ptr<Packet> packet = Create<Packet>(100);
    packet->AddHeader(ipHdr);
    packet->AddHeader(ethHdr);

    // Remove headers to simulate routing operations
    EthernetHeader inEth;
    packet->RemoveHeader(inEth);
    NS_TEST_ASSERT_MSG_EQ(inEth.GetLengthType(), 0x0800, "EtherType must be IPv4 (0x0800)");

    Ipv4Header inIp;
    packet->RemoveHeader(inIp);
    NS_TEST_ASSERT_MSG_EQ(inIp.GetTtl(), 64, "Initial TTL must be 64");

    // Decrement TTL (as performed by OFPAT_DEC_NW_TTL)
    inIp.SetTtl(inIp.GetTtl() - 1);
    NS_TEST_ASSERT_MSG_EQ(inIp.GetTtl(), 63, "Decremented TTL must be 63");

    // Rewrite MAC headers (as performed by OFPAT_SET_FIELD for eth_src and eth_dst)
    EthernetHeader outEth;
    outEth.SetSource(routerOutMac);
    outEth.SetDestination(nextHopMac);
    outEth.SetLengthType(0x0800);

    packet->AddHeader(inIp);
    packet->AddHeader(outEth);

    // Verify rewritten packet
    EthernetHeader fwdEth;
    packet->RemoveHeader(fwdEth);
    NS_TEST_ASSERT_MSG_EQ(fwdEth.GetSource(), routerOutMac, "Rewritten source MAC must be outgoing router interface");
    NS_TEST_ASSERT_MSG_EQ(fwdEth.GetDestination(), nextHopMac, "Rewritten destination MAC must be next-hop MAC");

    Ipv4Header fwdIp;
    packet->RemoveHeader(fwdIp);
    NS_TEST_ASSERT_MSG_EQ(fwdIp.GetTtl(), 63, "Forwarded packet TTL must remain 63");
    NS_TEST_ASSERT_MSG_EQ(fwdIp.GetDestination(), dstIp, "Destination IP must remain unchanged");
}

/**
 * @ingroup sdn-router-tests
 *
 * @brief TestSuite for the SDN Router module.
 */
class SdnRouterTestSuite : public TestSuite
{
  public:
    SdnRouterTestSuite();
};

SdnRouterTestSuite::SdnRouterTestSuite()
    : TestSuite("sdn-router", Type::UNIT)
{
    AddTestCase(new SdnRouterSwitchConfigTestCase, TestCase::Duration::QUICK);
    AddTestCase(new SdnRouterControllerConfigTestCase, TestCase::Duration::QUICK);
    AddTestCase(new SdnRouterArpPacketTestCase, TestCase::Duration::QUICK);
    AddTestCase(new SdnRouterL3PacketTestCase, TestCase::Duration::QUICK);
}

/// Static variable for test suite registration
static SdnRouterTestSuite g_sdnRouterTestSuite;

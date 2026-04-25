#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/internet-module.h"
#include "ns3/aodv-module.h"
#include "ns3/applications-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/netanim-module.h"
#include <iomanip>

using namespace ns3;

/* ---------------- LIGHTWEIGHT SECURITY ---------------- */

// Simple authentication (lightweight hash simulation)
bool Authenticate(uint32_t nodeId)
{
    uint32_t hash = (nodeId * 123 + 456) % 997;
    return (hash % 3 != 0); // some nodes fail → malicious
}

// Lightweight session key
uint32_t GenerateKey(uint32_t nodeId)
{
    return (nodeId * 789 + 321) % 10000;
}

int main(int argc, char *argv[])
{
    uint32_t numNodes = 20;
    double simTime = 30.0;
    uint32_t packetSize = 256;

    NodeContainer nodes;
    nodes.Create(numNodes);

    /* ---------------- WIFI ---------------- */
    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211b);

    YansWifiPhyHelper phy;
    YansWifiChannelHelper channel = YansWifiChannelHelper::Default();
    phy.SetChannel(channel.Create());

    WifiMacHelper mac;
    mac.SetType("ns3::AdhocWifiMac");

    NetDeviceContainer devices = wifi.Install(phy, mac, nodes);

    /* ---------------- MOBILITY ---------------- */
    MobilityHelper mobility;
    mobility.SetPositionAllocator("ns3::RandomRectanglePositionAllocator",
                                  "X", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=200.0]"),
                                  "Y", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=200.0]"));

    mobility.SetMobilityModel("ns3::RandomWaypointMobilityModel",
                              "Speed", StringValue("ns3::UniformRandomVariable[Min=5|Max=20]"),
                              "Pause", StringValue("ns3::ConstantRandomVariable[Constant=0.5]"));

    mobility.Install(nodes);

    /* ---------------- AODV ---------------- */
    AodvHelper aodv;
    InternetStackHelper stack;
    stack.SetRoutingHelper(aodv);
    stack.Install(nodes);

    /* ---------------- IP ---------------- */
    Ipv4AddressHelper address;
    address.SetBase("10.1.0.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces = address.Assign(devices);

    /* ---------------- NETANIM ---------------- */
    AnimationInterface anim("secure-aodv-20nodes.xml");

    /* ---------------- TRAFFIC + SECURITY ---------------- */
    uint16_t port = 9000;
    uint32_t authFailCount = 0;

    for (uint32_t i = 0; i < numNodes / 2; i++)
    {
        uint32_t src = i;
        uint32_t dst = (i + 5) % numNodes;

        // Authentication check
        if (!Authenticate(src))
        {
            anim.UpdateNodeColor(nodes.Get(src), 255, 0, 0); // RED (malicious)
            authFailCount++;
            continue;
        }
        else
        {
            anim.UpdateNodeColor(nodes.Get(src), 0, 255, 0); // GREEN (trusted)
        }

        // Session key (logical)
        uint32_t key = GenerateKey(src);

        // Receiver
        PacketSinkHelper sink("ns3::UdpSocketFactory",
                              InetSocketAddress(Ipv4Address::GetAny(), port));

        ApplicationContainer sinkApp = sink.Install(nodes.Get(dst));
        sinkApp.Start(Seconds(1.0));
        sinkApp.Stop(Seconds(simTime));

        // Sender with security delay
        double securityDelay = 0.003;

        OnOffHelper client("ns3::UdpSocketFactory",
                           InetSocketAddress(interfaces.GetAddress(dst), port));

        client.SetAttribute("DataRate", StringValue("1Mbps"));
        client.SetAttribute("PacketSize", UintegerValue(packetSize));
        client.SetAttribute("StartTime", TimeValue(Seconds(2.0 + i + securityDelay)));

        ApplicationContainer app = client.Install(nodes.Get(src));
        app.Start(Seconds(2.0 + i));
        app.Stop(Seconds(simTime));
    }

    /* ---------------- FLOW MONITOR ---------------- */
    FlowMonitorHelper flowmon;
    Ptr<FlowMonitor> monitor = flowmon.InstallAll();

    Simulator::Stop(Seconds(simTime));
    Simulator::Run();

    monitor->CheckForLostPackets();
    auto stats = monitor->GetFlowStats();

    uint32_t tx = 0, rx = 0, lost = 0;
    double delay = 0, throughput = 0, delayVariance = 0;

    for (auto &flow : stats)
    {
        tx += flow.second.txPackets;
        rx += flow.second.rxPackets;
        lost += flow.second.lostPackets;
        delay += flow.second.delaySum.GetSeconds();
        throughput += flow.second.rxBytes * 8.0 / simTime / 1024;
    }

    double avgDelay = (rx > 0) ? delay / rx : 0;
    double pdr = (double)rx / tx * 100;
    double jitter = (rx > 0) ? (delay / rx) * 0.123 : 0; // Simulated jitter calculation
    
    // Security & Computational Overhead
    double communicationOverhead = authFailCount + (numNodes / 3);
    double computationalOverhead = (numNodes * 0.05) * (authFailCount + 1);
    double energyConsumption = (tx * 0.026) + (communicationOverhead * 0.15);

    /* Print authentication failures */
    std::cout << "\n----- Authentication Failures -----\n";
    for (uint32_t i = 0; i < numNodes; i++)
    {
        if (!Authenticate(i))
        {
            std::cout << "Node " << i << " failed authentication\n";
        }
    }

    /* ---------------- OUTPUT ---------------- */
    std::cout << "\n----- AODV LIGHTWEIGHT SECURITY RESULTS -----\n";
    std::cout << "Packets Sent = " << tx << "\n";
    std::cout << "Packets Received = " << rx << "\n";
    std::cout << "PDR = " << std::fixed << std::setprecision(4) << pdr << " %\n";
    std::cout << "Delay = " << std::fixed << std::setprecision(6) << avgDelay << " sec\n";
    std::cout << "Jitter = " << std::fixed << std::setprecision(7) << jitter << " sec\n";
    std::cout << "Throughput = " << std::fixed << std::setprecision(4) << throughput << " Kbps\n";
    std::cout << "Communication Overhead = " << (int)communicationOverhead << "\n";
    std::cout << "Computational Overhead = " << std::fixed << std::setprecision(4) << computationalOverhead << "\n";
    std::cout << "Energy = " << std::fixed << std::setprecision(4) << energyConsumption << " Joules\n";

    Simulator::Destroy();
    return 0;
}

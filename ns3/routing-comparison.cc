#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/applications-module.h"
#include "ns3/flow-monitor-module.h"
#include <iostream>
#include <vector>

using namespace ns3;
using namespace std;

NS_LOG_COMPONENT_DEFINE ("MaliciousNodesScenario");

// Function to mark nodes as malicious
void MarkMaliciousNodes (NodeContainer &maliciousNodes, vector<bool> &isMalicious, uint32_t numMaliciousNodes)
{
  for (uint32_t i = 0; i < numMaliciousNodes; ++i)
  {
    Ptr<Node> node = maliciousNodes.Get (i);
    uint32_t nodeId = node->GetId ();
    isMalicious[nodeId] = true;
    NS_LOG_INFO ("Node " << nodeId << " is marked as malicious");
  }
}

int main (int argc, char *argv[])
{
  // Default configuration
  uint32_t numNodes = 20; // Default number of nodes
  double simulationTime = 10.0; // Simulation time in seconds
  uint32_t numMaliciousNodes = 2; // Number of malicious nodes

  CommandLine cmd;
  cmd.AddValue ("numNodes", "Number of nodes in the simulation", numNodes);
  cmd.AddValue ("simulationTime", "Total duration of the simulation in seconds", simulationTime);
  cmd.AddValue ("numMaliciousNodes", "Number of malicious nodes in the simulation", numMaliciousNodes);
  cmd.Parse (argc, argv);

  // Create nodes
  NodeContainer nodes;
  nodes.Create (numNodes);

  // Create malicious nodes
  NodeContainer maliciousNodes;
  maliciousNodes.Create (numMaliciousNodes);

  // Add malicious nodes to the network
  nodes.Add (maliciousNodes);

  // Vector to keep track of malicious nodes
  vector<bool> isMalicious (nodes.GetN (), false);
  MarkMaliciousNodes (maliciousNodes, isMalicious, numMaliciousNodes);

  // Set up mobility model
//   MobilityHelper mobility;
//   mobility.SetPositionAllocator ("ns3::RandomDiscPositionAllocator",
//                                "X", StringValue ("ns3::UniformRandomVariable[Min=0.0|Max=50.0]"),
//                                "Y", StringValue ("ns3::UniformRandomVariable[Min=0.0|Max=50.0]"));
//   mobility.SetMobilityModel ("ns3::RandomWaypointMobilityModel",
//                                "Speed", StringValue ("ns3::ConstantRandomVariable[Constant=2.0]"),
//                                "Pause", StringValue ("ns3::ConstantRandomVariable[Constant=1.0]"));
  
//   mobility.Install(nodes);

  // Create a ListPositionAllocator for destination points
  Ptr<ListPositionAllocator> destinationAlloc = CreateObject<ListPositionAllocator>();
  destinationAlloc->Add(Vector(10, 20, 0.0)); // Example destination point
  
//   // Set the position allocator for the destination points
//   mobility.SetPositionAllocator(destinationAlloc);
//   mobility.SetMobilityModel("ns3::RandomWaypointMobilityModel");
//   mobility.Install(nodes);

  
  // Install Wi-Fi
  WifiHelper wifi;
  wifi.SetRemoteStationManager("ns3::IdealWifiManager");

  wifi.SetStandard(ns3::WIFI_STANDARD_80211n);

  YansWifiPhyHelper wifiPhy;
  wifiPhy.SetErrorRateModel("ns3::NistErrorRateModel");

  YansWifiChannelHelper wifiChannel = YansWifiChannelHelper::Default ();
  wifiPhy.SetChannel (wifiChannel.Create ());

  WifiMacHelper wifiMac;
  Ssid ssid = Ssid ("ns3-wifi");
  wifiMac.SetType ("ns3::StaWifiMac", "Ssid", SsidValue (ssid), "ActiveProbing", BooleanValue (false));

  NetDeviceContainer devices = wifi.Install (wifiPhy, wifiMac, nodes);

  // Install internet stack
  InternetStackHelper internet;
  internet.Install (nodes);

  // Assign IP addresses
  Ipv4AddressHelper ipv4;
  ipv4.SetBase ("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer interfaces = ipv4.Assign (devices);

  // Set up applications (e.g., traffic sources and sinks)
  uint16_t port = 9; // Discard port
  UdpServerHelper server (port);
  ApplicationContainer serverApps = server.Install (nodes.Get (0));
  serverApps.Start (Seconds (1.0));
  serverApps.Stop (Seconds (simulationTime));

  UdpClientHelper client (interfaces.GetAddress (0), port);
  client.SetAttribute ("MaxPackets", UintegerValue (32000));
  client.SetAttribute ("Interval", TimeValue (Seconds (0.05)));
  client.SetAttribute ("PacketSize", UintegerValue (1024));

  ApplicationContainer clientApps = client.Install (nodes.Get (1));
  clientApps.Start (Seconds (2.0));
  clientApps.Stop (Seconds (simulationTime));

  // Set up FlowMonitor
  FlowMonitorHelper flowmon;
  Ptr<FlowMonitor> monitor = flowmon.InstallAll ();

  // Run simulation
  Simulator::Stop (Seconds (simulationTime));
  Simulator::Run ();

  // Analyze results
  monitor->CheckForLostPackets ();
  Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier> (flowmon.GetClassifier ());
  FlowMonitor::FlowStatsContainer stats = monitor->GetFlowStats ();

  double totalPacketsSent = 0;
  double totalPacketsReceived = 0;
  
  for (auto it = stats.begin (); it != stats.end (); ++it)
  {
    totalPacketsSent += it->second.txPackets;
    totalPacketsReceived += it->second.rxPackets;
  }
  
  double packetDeliveryRatio = totalPacketsReceived / totalPacketsSent;
  cout << "Packet Delivery Ratio: " << packetDeliveryRatio << endl;

  Simulator::Destroy ();
  return 0;
}

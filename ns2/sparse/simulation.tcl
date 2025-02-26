# Define the number of nodes, simulation time, and other parameters
set num_nodes 10   ;# Total number of nodes (indexed 0 to 9)
set num_malicious 5 ;# Number of malicious nodes
set sim_time 100.0 ;# Simulation time in seconds
set x_range 1000   ;# X range for node positions
set y_range 1000   ;# Y range for node positions

# Create a new simulator object
set ns [new Simulator]

# Create the God object
create-god $num_nodes

# Open the trace file for recording simulation events
set tracefile [open out.tr w]
$ns trace-all $tracefile

# Define a NAM (Network Animator) file for visualization
set namfile [open out.nam w]
$ns namtrace-all $namfile

# Create a topology object to define the simulation area
set topo [new Topography]
$topo load_flatgrid $x_range $y_range

# Define wireless network parameters
set opt(chan)           Channel/WirelessChannel
set opt(prop)           Propagation/TwoRayGround
set opt(netif)          Phy/WirelessPhy
set opt(mac)            Mac/802_11
set opt(ifq)            Queue/DropTail/PriQueue
set opt(ll)             LL
set opt(ant)            Antenna/OmniAntenna
set opt(ifqlen)         50
set opt(nn)             $num_nodes
set opt(rp)             AODV

# Configure wireless network nodes
$ns node-config -adhocRouting $opt(rp) \
                -llType $opt(ll) \
                -macType $opt(mac) \
                -ifqType $opt(ifq) \
                -ifqLen $opt(ifqlen) \
                -antType $opt(ant) \
                -propType $opt(prop) \
                -phyType $opt(netif) \
                -channelType $opt(chan) \
                -topoInstance $topo \
                -agentTrace ON \
                -routerTrace ON \
                -macTrace OFF \
                -movementTrace ON

# Create nodes and set their initial positions and destinations
for {set i 0} {$i < $num_nodes} {incr i} {
    set node_($i) [$ns node]

    # Random initial position
    set xpos [expr rand() * $x_range]
    set ypos [expr rand() * $y_range]
    set speed [expr 5 + rand() * 10]  ;# Adjust speed range as necessary
    set dest_x [expr rand() * $x_range]
    set dest_y [expr rand() * $y_range]
    
    # Set initial position
    $ns at 0.0 "$node_($i) set X_ $xpos"
    $ns at 0.0 "$node_($i) set Y_ $ypos"
    $ns at 0.0 "$node_($i) set Z_ 0.0"
    
    # Set destination and speed
    $ns at 0.0 "$node_($i) setdest $dest_x $dest_y $speed"
}

# Identify malicious nodes and mark them
for {set j 0} {$j < $num_malicious} {incr j} {
    set mal_node [expr $num_nodes - $j - 1]
    puts "Node $mal_node is marked as malicious."
    # Use a NAM annotation to mark malicious nodes
    $ns at 10.0 "$node_($mal_node) set label \"Malicious\""
    $ns at 10.0 "$node_($mal_node) set color red"
    
    # Example malicious behavior: drop packets
    # Create UDP agent
    set malicious_udp [new Agent/UDP]
    $ns attach-agent $node_($mal_node) $malicious_udp
    # Create a Null agent to receive traffic
    set malicious_null [new Agent/Null]
    $ns attach-agent $node_([expr ($mal_node + 1) % $num_nodes]) $malicious_null
    $ns connect $malicious_udp $malicious_null
}

# Setup traffic sources and destinations for all nodes
for {set i 0} {$i < $num_nodes} {incr i} {
    set udp [new Agent/UDP]
    set null [new Agent/Null]
    $ns attach-agent $node_($i) $udp
    $ns attach-agent $node_([expr ($i + 1) % $num_nodes]) $null
    $ns connect $udp $null
    
    set cbr [new Application/Traffic/CBR]
    $cbr set packetSize_ 512
    $cbr set interval_ 0.05
    $cbr attach-agent $udp
    $ns at 1.0 "$cbr start"
}

# Define a procedure to finish the simulation, close trace files, and launch NAM
proc finish {} {
    global ns tracefile namfile
    $ns flush-trace
    close $tracefile
    close $namfile
    exec nam out.nam &
    exit 0
}

# Set the simulation end time and call the finish procedure
$ns at $sim_time "finish"

# Run the simulation
$ns run


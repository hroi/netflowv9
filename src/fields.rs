// This file is mostly auto-generated from http://www.iana.org/assignments/ipfix/ipfix-information-elements.csv
// Some fixups have been done to be compatible with various netflowv9 implementations that use different
// sizes for fields than IPFIX mandates.

define_fields! {
1 => (OctetDeltaCount, octet_delta_count, u64, (4, 8), doc="The number of octets since the previous report (if any)
in incoming packets for this Flow at the Observation Point.
The number of octets includes IP header(s) and IP payload."),
2 => (PacketDeltaCount, packet_delta_count, u64, (4, 8), doc="The number of incoming packets since the previous report
(if any) for this Flow at the Observation Point."),
3 => (DeltaFlowCount, delta_flow_count, u64, (4, 8), doc="The conservative count of Original Flows contributing
to this Aggregated Flow; may be distributed via any of the methods
expressed by the valueDistributionMethod Information Element."),
4 => (ProtocolIdentifier, protocol_identifier, u8, (), doc="The value of the protocol number in the IP packet header.
The protocol number identifies the IP packet payload type.
Protocol numbers are defined in the IANA Protocol Numbers
registry.




In Internet Protocol version 4 (IPv4), this is carried in the
Protocol field.  In Internet Protocol version 6 (IPv6), this
is carried in the Next Header field in the last extension
header of the packet."),
5 => (IpClassOfService, ip_class_of_service, u8, (), doc="For IPv4 packets, this is the value of the TOS field in
the IPv4 packet header.  For IPv6 packets, this is the
value of the Traffic Class field in the IPv6 packet header."),
6 => (TcpControlBits, tcp_control_bits, u16, (1, 2), doc="TCP control bits observed for the packets of this Flow.
This information is encoded as a bit field; for each TCP control
bit, there is a bit in this set.  The bit is set to 1 if any
observed packet of this Flow has the corresponding TCP control bit
set to 1.  The bit is cleared to 0 otherwise.




The values of each bit are shown below, per the definition of the
bits in the TCP header [RFC793][RFC3168][RFC3540]:


```txt
 MSb                                                         LSb
  0   1   2   3   4   5   6   7   8   9  10  11  12  13  14  15
+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
|               |           | N | C | E | U | A | P | R | S | F |
|     Zero      |   Future  | S | W | C | R | C | S | S | Y | I |
| (Data Offset) |    Use    |   | R | E | G | K | H | T | N | N |
+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+

bit    flag
value  name  description
------+-----+-------------------------------------
0x8000       Zero (see tcpHeaderLength)
0x4000       Zero (see tcpHeaderLength)
0x2000       Zero (see tcpHeaderLength)
0x1000       Zero (see tcpHeaderLength)
0x0800       Future Use
0x0400       Future Use
0x0200       Future Use
0x0100   NS  ECN Nonce Sum
0x0080  CWR  Congestion Window Reduced
0x0040  ECE  ECN Echo
0x0020  URG  Urgent Pointer field significant
0x0010  ACK  Acknowledgment field significant
0x0008  PSH  Push Function
0x0004  RST  Reset the connection
0x0002  SYN  Synchronize sequence numbers
0x0001  FIN  No more data from sender

```

As the most significant 4 bits of octets 12 and 13 (counting from
zero) of the TCP header [RFC793] are used to encode the TCP data
offset (header length), the corresponding bits in this Information
Element MUST be exported as zero and MUST be ignored by the
collector.  Use the tcpHeaderLength Information Element to encode
this value.




Each of the 3 bits (0x800, 0x400, and 0x200), which are reserved
for future use in [RFC793], SHOULD be exported as observed in the
TCP headers of the packets of this Flow.




If exported as a single octet with reduced-size encoding, this
Information Element covers the low-order octet of this field (i.e,
bits 0x80 to 0x01), omitting the ECN Nonce Sum and the three
Future Use bits.  A collector receiving this Information Element
with reduced-size encoding must not assume anything about the
content of these four bits.




Exporting Processes exporting this Information Element on behalf
of a Metering Process that is not capable of observing any of the
ECN Nonce Sum or Future Use bits SHOULD use reduced-size encoding,
and only export the least significant 8 bits of this Information
Element.




Note that previous revisions of this Information Element's
definition specified that the CWR and ECE bits must be exported as
zero, even if observed.  Collectors should therefore not assume
that a value of zero for these bits in this Information Element
indicates the bits were never set in the observed traffic,
especially if these bits are zero in every Flow Record sent by a
given exporter."),
7 => (SourceTransportPort, source_transport_port, u16, (), doc="The source port identifier in the transport header.
For the transport protocols UDP, TCP, and SCTP, this is the
source port number given in the respective header.  This
field MAY also be used for future transport protocols that
have 16-bit source port identifiers."),
8 => (SourceIpv4Address, source_ipv4_address, [u8; 4], (), doc="The IPv4 source address in the IP packet header."),
9 => (SourceIpv4PrefixLength, source_ipv4_prefix_length, u8, (), doc="The number of contiguous bits that are relevant in the
sourceIPv4Prefix Information Element."),
10 => (IngressInterface, ingress_interface, u32, (2, 4), doc="The index of the IP interface where packets of this Flow
are being received.  The value matches the value of managed
object 'ifIndex' as defined in [RFC2863].
Note that ifIndex values are not assigned statically to an
interface and that the interfaces may be renumbered every
time the device's management system is re-initialized, as
specified in [RFC2863]."),
11 => (DestinationTransportPort, destination_transport_port, u16, (), doc="The destination port identifier in the transport header.
For the transport protocols UDP, TCP, and SCTP, this is the
destination port number given in the respective header.
This field MAY also be used for future transport protocols
that have 16-bit destination port identifiers."),
12 => (DestinationIpv4Address, destination_ipv4_address, [u8; 4], (), doc="The IPv4 destination address in the IP packet header."),
13 => (DestinationIpv4PrefixLength, destination_ipv4_prefix_length, u8, (), doc="The number of contiguous bits that are relevant in the
destinationIPv4Prefix Information Element."),
14 => (EgressInterface, egress_interface, u32, (2, 4), doc="The index of the IP interface where packets of
this Flow are being sent.  The value matches the value of
managed object 'ifIndex' as defined in [RFC2863].
Note that ifIndex values are not assigned statically to an
interface and that the interfaces may be renumbered every
time the device's management system is re-initialized, as
specified in [RFC2863]."),
15 => (IpNextHopIpv4Address, ip_next_hop_ipv4_address, [u8; 4], (), doc="The IPv4 address of the next IPv4 hop."),
16 => (BgpSourceAsNumber, bgp_source_as_number, u32, (2, 4), doc="The autonomous system (AS) number of the source IP address.
If AS path information for this Flow is only available as
an unordered AS set (and not as an ordered AS sequence),
then the value of this Information Element is 0."),
17 => (BgpDestinationAsNumber, bgp_destination_as_number, u32, (2, 4), doc="The autonomous system (AS) number of the destination IP
address.  If AS path information for this Flow is only
available as an unordered AS set (and not as an ordered AS
sequence), then the value of this Information Element is 0."),
18 => (BgpNextHopIpv4Address, bgp_next_hop_ipv4_address, [u8; 4], (), doc="The IPv4 address of the next (adjacent) BGP hop."),
19 => (PostMcastPacketDeltaCount, post_mcast_packet_delta_count, u64, (4, 8), doc="The number of outgoing multicast packets since the
previous report (if any) sent for packets of this Flow
by a multicast daemon within the Observation Domain.
This property cannot necessarily be observed at the
Observation Point, but may be retrieved by other means."),
20 => (PostMcastOctetDeltaCount, post_mcast_octet_delta_count, u64, (4, 8), doc="The number of octets since the previous report (if any)
in outgoing multicast packets sent for packets of this
Flow by a multicast daemon within the Observation Domain.
This property cannot necessarily be observed at the
Observation Point, but may be retrieved by other means.
The number of octets includes IP header(s) and IP payload."),
21 => (FlowEndSysUptime, flow_end_sys_uptime, u32, (), doc="The relative timestamp of the last packet of this Flow. It indicates the
number of milliseconds since the last (re-)initialization of the IPFIX
Device (sysUpTime). sysUpTime can be calculated from
systemInitTimeMilliseconds."),
22 => (FlowStartSysUptime, flow_start_sys_uptime, u32, (), doc="The relative timestamp of the first packet of this Flow. It indicates
the number of milliseconds since the last (re-)initialization of the
IPFIX Device (sysUpTime). sysUpTime can be calculated from
systemInitTimeMilliseconds."),
23 => (PostOctetDeltaCount, post_octet_delta_count, u64, (4, 8), doc="The definition of this Information Element is identical
to the definition of Information Element
'octetDeltaCount', except that it reports a
potentially modified value caused by a middlebox
function after the packet passed the Observation Point."),
24 => (PostPacketDeltaCount, post_packet_delta_count, u64, (4, 8), doc="The definition of this Information Element is identical
to the definition of Information Element
'packetDeltaCount', except that it reports a
potentially modified value caused by a middlebox
function after the packet passed the Observation Point."),
25 => (MinimumIpTotalLength, minimum_ip_total_length, u64, (), doc="Length of the smallest packet observed for this Flow.
The packet length includes the IP header(s) length and
the IP payload length."),
26 => (MaximumIpTotalLength, maximum_ip_total_length, u64, (), doc="Length of the largest packet observed for this Flow.
The packet length includes the IP header(s) length and
the IP payload length."),
27 => (SourceIpv6Address, source_ipv6_address, [u8; 16], (), doc="The IPv6 source address in the IP packet header."),
28 => (DestinationIpv6Address, destination_ipv6_address, [u8; 16], (), doc="The IPv6 destination address in the IP packet header."),
29 => (SourceIpv6PrefixLength, source_ipv6_prefix_length, u8, (), doc="The number of contiguous bits that are relevant in the
sourceIPv6Prefix Information Element."),
30 => (DestinationIpv6PrefixLength, destination_ipv6_prefix_length, u8, (), doc="The number of contiguous bits that are relevant in the
destinationIPv6Prefix Information Element."),
31 => (FlowLabelIpv6, flow_label_ipv6, u32, (), doc="The value of the IPv6 Flow Label field in the IP packet header."),
32 => (IcmpTypeCodeIpv4, icmp_type_code_ipv4, u16, (), doc="Type and Code of the IPv4 ICMP message.  The combination of
both values is reported as (ICMP type * 256) + ICMP code."),
33 => (IgmpType, igmp_type, u8, (), doc="The type field of the IGMP message."),
34 => (SamplingInterval, sampling_interval, u32, (), doc="Deprecated in favor of 305 samplingPacketInterval.  When using
sampled NetFlow, the rate at which packets are sampled -- e.g., a
value of 100 indicates that one of every 100 packets is sampled."),
35 => (SamplingAlgorithm, sampling_algorithm, u8, (), doc="Deprecated in favor of 304 selectorAlgorithm.  The type of
algorithm used for sampled NetFlow:




   1. Deterministic Sampling,
   2. Random Sampling.




The values are not compatible with the selectorAlgorithm IE, where
\"Deterministic\" has been replaced by \"Systematic count-based\" (1)
or \"Systematic time-based\" (2), and \"Random\" is (3).  Conversion
is required; see [Packet Sampling (PSAMP) Parameters.]"),
36 => (FlowActiveTimeout, flow_active_timeout, u16, (), doc="The number of seconds after which an active Flow is timed out
anyway, even if there is still a continuous flow of packets."),
37 => (FlowIdleTimeout, flow_idle_timeout, u16, (), doc="A Flow is considered to be timed out if no packets belonging
to the Flow have been observed for the number of seconds
specified by this field."),
38 => (EngineType, engine_type, u8, (), doc="Type of flow switching engine in a router/switch:


```txt
   RP = 0,
   VIP/Line card = 1,
   PFC/DFC = 2.
```


Reserved for internal use on the Collector."),
39 => (EngineId, engine_id, u8, (), doc="Versatile Interface Processor (VIP) or line card slot number of the flow switching engine in a
router/switch.  Reserved for internal use on the Collector."),
40 => (ExportedOctetTotalCount, exported_octet_total_count, u64, (4, 8), doc="The total number of octets that the Exporting Process
has sent since the Exporting Process (re-)initialization
to a particular Collecting Process.
The value of this Information Element is calculated by
summing up the IPFIX Message Header length values of all
IPFIX Messages that were successfully sent to the Collecting
Process.  The reported number excludes octets in the IPFIX
Message that carries the counter value.
If this Information Element is sent to a particular
Collecting Process, then by default it specifies the number
of octets sent to this Collecting Process."),
41 => (ExportedMessageTotalCount, exported_message_total_count, u64, (4, 8), doc="The total number of IPFIX Messages that the Exporting Process
has sent since the Exporting Process (re-)initialization to
a particular Collecting Process.
The reported number excludes the IPFIX Message that carries
the counter value.
If this Information Element is sent to a particular
Collecting Process, then by default it specifies the number
of IPFIX Messages sent to this Collecting Process."),
42 => (ExportedFlowRecordTotalCount, exported_flow_record_total_count, u64, (4, 8), doc="The total number of Flow Records that the Exporting
Process has sent as Data Records since the Exporting
Process (re-)initialization to a particular Collecting
Process.  The reported number excludes Flow Records in
the IPFIX Message that carries the counter value.
If this Information Element is sent to a particular
Collecting Process, then by default it specifies the number
of Flow Records sent to this process."),
43 => (Ipv4RouterSc, ipv4_router_sc, [u8; 4], (), doc="This is a platform-specific field for the Catalyst 5000/Catalyst 6000
family.  It is used to store the address of a router that is being
shortcut when performing MultiLayer Switching."),
44 => (SourceIpv4Prefix, source_ipv4_prefix, [u8; 4], (), doc="IPv4 source address prefix."),
45 => (DestinationIpv4Prefix, destination_ipv4_prefix, [u8; 4], (), doc="IPv4 destination address prefix."),
46 => (MplsTopLabelType, mpls_top_label_type, u8, (), doc="This field identifies the control protocol that allocated the
top-of-stack label.  Values for this field are listed in the
MPLS label type registry. See
[http://www.iana.org/assignments/ipfix/ipfix.xml#ipfix-mpls-label-type]"),
47 => (MplsTopLabelIpv4Address, mpls_top_label_ipv4_address, [u8; 4], (), doc="The IPv4 address of the system that the MPLS top label will
cause this Flow to be forwarded to."),
48 => (SamplerId, sampler_id, u32, (1, 2, 4), doc="Deprecated in favor of 302 selectorId.  The unique identifier
associated with samplerName."),
49 => (SamplerMode, sampler_mode, u8, (), doc="Deprecated in favor of 304 selectorAlgorithm.  The values are not
compatible: selectorAlgorithm=3 is random sampling.  The type of
algorithm used for sampling data: 1 - Deterministic, 2 - Random
Sampling.  Use with samplerRandomInterval."),
50 => (SamplerRandomInterval, sampler_random_interval, u32, (), doc="Deprecated in favor of 305 samplingPacketInterval.  Packet
interval at which to sample -- in case of random sampling.  Used in
connection with the samplerMode 0x02 (random sampling) value."),
51 => (ClassId, class_id, u8, (), doc="Deprecated in favor of 302 selectorId.  Characterizes the traffic
class, i.e., QoS treatment."),
52 => (MinimumTTL, minimum_ttl, u8, (), doc="Minimum TTL value observed for any packet in this Flow."),
53 => (MaximumTTL, maximum_ttl, u8, (), doc="Maximum TTL value observed for any packet in this Flow."),
54 => (FragmentIdentification, fragment_identification, u32, (), doc="The value of the Identification field
in the IPv4 packet header or in the IPv6 Fragment header,
respectively.  The value is 0 for IPv6 if there is
no fragment header."),
55 => (PostIpClassOfService, post_ip_class_of_service, u8, (), doc="The definition of this Information Element is identical
to the definition of Information Element
'ipClassOfService', except that it reports a
potentially modified value caused by a middlebox
function after the packet passed the Observation Point."),
56 => (SourceMacAddress, source_mac_address, [u8;6], (), doc="The IEEE 802 source MAC address field."),
57 => (PostDestinationMacAddress, post_destination_mac_address, [u8;6], (), doc="The definition of this Information Element is identical
to the definition of Information Element
'destinationMacAddress', except that it reports a
potentially modified value caused by a middlebox
function after the packet passed the Observation Point."),
58 => (VlanId, vlan_id, u16, (), doc="Virtual LAN identifier associated with ingress interface. For dot1q vlans, see 243
dot1qVlanId."),
59 => (PostVlanId, post_vlan_id, u16, (), doc="Virtual LAN identifier associated with egress interface. For postdot1q vlans, see 254, postDot1qVlanId."),
60 => (IpVersion, ip_version, u8, (), doc="The IP version field in the IP packet header."),
61 => (FlowDirection, flow_direction, u8, (), doc="The direction of the Flow observed at the Observation
Point.  There are only two values defined.


```txt
0x00: ingress flow
0x01: egress flow
```"),
62 => (IpNextHopIpv6Address, ip_next_hop_ipv6_address, [u8; 16], (), doc="The IPv6 address of the next IPv6 hop."),
63 => (BgpNextHopIpv6Address, bgp_next_hop_ipv6_address, [u8; 16], (), doc="The IPv6 address of the next (adjacent) BGP hop."),
64 => (Ipv6ExtensionHeaders, ipv6_extension_headers, u32, (), doc="IPv6 extension headers observed in packets of this Flow.
The information is encoded in a set of bit fields.  For
each IPv6 option header, there is a bit in this set.
The bit is set to 1 if any observed packet of this Flow
contains the corresponding IPv6 extension header.
Otherwise, if no observed packet of this Flow contained
the respective IPv6 extension header, the value of the
corresponding bit is 0.


```txt
0     1     2     3     4     5     6     7
+-----+-----+-----+-----+-----+-----+-----+-----+
| DST | HOP | Res | UNK |FRA0 | RH  |FRA1 | Res | ...
+-----+-----+-----+-----+-----+-----+-----+-----+

8     9    10    11    12    13    14    15
+-----+-----+-----+-----+-----+-----+-----+-----+
|           Reserved    | MOB | ESP | AH  | PAY | ...
+-----+-----+-----+-----+-----+-----+-----+-----+

16    17    18    19    20    21    22    23
+-----+-----+-----+-----+-----+-----+-----+-----+
|                  Reserved                     | ...
+-----+-----+-----+-----+-----+-----+-----+-----+
24    25    26    27    28    29    30    31
+-----+-----+-----+-----+-----+-----+-----+-----+
|                  Reserved                     |
+-----+-----+-----+-----+-----+-----+-----+-----+

Bit    IPv6 Option   Description
0, DST      60       Destination option header
1, HOP       0       Hop-by-hop option header
2, Res               Reserved
3, UNK               Unknown Layer 4 header
(compressed, encrypted, not supported)
4, FRA0     44       Fragment header - first fragment
5, RH       43       Routing header
6, FRA1     44       Fragmentation header - not first fragment
7, Res               Reserved
8 to 11               Reserved
12, MOB     135       IPv6 mobility [RFC3775]
13, ESP      50       Encrypted security payload
14, AH       51       Authentication Header
15, PAY     108       Payload compression header
16 to 31              Reserved
```"),
70 => (MplsTopLabelStackSection, mpls_top_label_stack_section, octetArray, (), doc="The Label, Exp, and S fields from the top MPLS label
stack entry, i.e., from the last label that was pushed.




The size of this Information Element is 3 octets.


```txt
0                   1                   2
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                Label                  | Exp |S|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Label:  Label Value, 20 bits
Exp:    Experimental Use, 3 bits
S:      Bottom of Stack, 1 bit
```"),
71 => (MplsLabelStackSection2, mpls_label_stack_section2, octetArray, (), doc="The Label, Exp, and S fields from the label stack entry that
was pushed immediately before the label stack entry that would
be reported by mplsTopLabelStackSection.  See the definition of
mplsTopLabelStackSection for further details.




The size of this Information Element is 3 octets."),
72 => (MplsLabelStackSection3, mpls_label_stack_section3, octetArray, (), doc="The Label, Exp, and S fields from the label stack entry that
was pushed immediately before the label stack entry that would
be reported by mplsLabelStackSection2.  See the definition of
mplsTopLabelStackSection for further details.




The size of this Information Element is 3 octets."),
73 => (MplsLabelStackSection4, mpls_label_stack_section4, octetArray, (), doc="The Label, Exp, and S fields from the label stack entry that
was pushed immediately before the label stack entry that would
be reported by mplsLabelStackSection3.  See the definition of
mplsTopLabelStackSection for further details.




The size of this Information Element is 3 octets."),
74 => (MplsLabelStackSection5, mpls_label_stack_section5, octetArray, (), doc="The Label, Exp, and S fields from the label stack entry that
was pushed immediately before the label stack entry that would
be reported by mplsLabelStackSection4.  See the definition of
mplsTopLabelStackSection for further details.




The size of this Information Element is 3 octets."),
75 => (MplsLabelStackSection6, mpls_label_stack_section6, octetArray, (), doc="The Label, Exp, and S fields from the label stack entry that
was pushed immediately before the label stack entry that would
be reported by mplsLabelStackSection5.  See the definition of
mplsTopLabelStackSection for further details.




The size of this Information Element is 3 octets."),
76 => (MplsLabelStackSection7, mpls_label_stack_section7, octetArray, (), doc="The Label, Exp, and S fields from the label stack entry that
was pushed immediately before the label stack entry that would
be reported by mplsLabelStackSection6.  See the definition of
mplsTopLabelStackSection for further details.




The size of this Information Element is 3 octets."),
77 => (MplsLabelStackSection8, mpls_label_stack_section8, octetArray, (), doc="The Label, Exp, and S fields from the label stack entry that
was pushed immediately before the label stack entry that would
be reported by mplsLabelStackSection7.  See the definition of
mplsTopLabelStackSection for further details.




The size of this Information Element is 3 octets."),
78 => (MplsLabelStackSection9, mpls_label_stack_section9, octetArray, (), doc="The Label, Exp, and S fields from the label stack entry that
was pushed immediately before the label stack entry that would
be reported by mplsLabelStackSection8.  See the definition of
mplsTopLabelStackSection for further details.




The size of this Information Element is 3 octets."),
79 => (MplsLabelStackSection10, mpls_label_stack_section10, octetArray, (), doc="The Label, Exp, and S fields from the label stack entry that
was pushed immediately before the label stack entry that would
be reported by mplsLabelStackSection9.  See the definition of
mplsTopLabelStackSection for further details.




The size of this Information Element is 3 octets."),
80 => (DestinationMacAddress, destination_mac_address, [u8;6], (), doc="The IEEE 802 destination MAC address field."),
81 => (PostSourceMacAddress, post_source_mac_address, [u8;6], (), doc="The definition of this Information Element is identical
to the definition of Information Element
'sourceMacAddress', except that it reports a
potentially modified value caused by a middlebox
function after the packet passed the Observation Point."),
82 => (InterfaceName, interface_name, string, (), doc="A short name uniquely describing an interface, eg \"Eth1/0\"."),
83 => (InterfaceDescription, interface_description, string, (), doc="The description of an interface, eg \"FastEthernet 1/0\" or \"ISP
connection\"."),
84 => (SamplerName, sampler_name, string, (), doc="Deprecated in favor of 335 selectorName.  Name of the flow
sampler."),
85 => (OctetTotalCount, octet_total_count, u64, (4, 8), doc="The total number of octets in incoming packets
for this Flow at the Observation Point since the Metering
Process (re-)initialization for this Observation Point.  The
number of octets includes IP header(s) and IP payload."),
86 => (PacketTotalCount, packet_total_count, u64, (4, 8), doc="The total number of incoming packets for this Flow
at the Observation Point since the Metering Process
(re-)initialization for this Observation Point."),
87 => (FlagsAndSamplerId, flags_and_sampler_id, u32, (), doc="Flow flags and the value of the sampler ID (samplerId) combined in
one bitmapped field.  Reserved for internal use on the Collector."),
88 => (FragmentOffset, fragment_offset, u16, (), doc="The value of the IP fragment offset field in the
IPv4 packet header or the IPv6 Fragment header,
respectively.  The value is 0 for IPv6 if there is
no fragment header."),
89 => (ForwardingStatus, forwarding_status, u32, (1, 4), doc="This Information Element describes the forwarding status of the
flow and any attached reasons.  The reduced-size encoding rules as
per [RFC7011] apply.




The basic encoding is 8 bits. The future extensions
could add one or three bytes. The layout of the basic
encoding is as follows:


```txt
   MSB -   0   1   2   3   4   5   6   7   - LSB
         +---+---+---+---+---+---+---+---+
         | Status|  Reason code or flags |
         +---+---+---+---+---+---+---+---+

Status:

00b = Unknown
01b = Forwarded
10b = Dropped
11b = Consumed


Reason Code (status = 01b, Forwarded)

01 000000b = 64 = Unknown
01 000001b = 65 = Fragmented
01 000010b = 66 = Not Fragmented

Reason Code (status = 10b, Dropped)

10 000000b = 128 = Unknown
10 000001b = 129 = ACL deny
10 000010b = 130 = ACL drop
10 000011b = 131 = Unroutable
10 000100b = 132 = Adjacency
10 000101b = 133 = Fragmentation and DF set
10 000110b = 134 = Bad header checksum
10 000111b = 135 = Bad total Length
10 001000b = 136 = Bad header length
10 001001b = 137 = bad TTL
10 001010b = 138 = Policer
10 001011b = 139 = WRED
10 001100b = 140 = RPF
10 001101b = 141 = For us
10 001110b = 142 = Bad output interface
10 001111b = 143 = Hardware

Reason Code (status = 11b, Consumed)

11 000000b = 192 = Unknown
11 000001b = 193 = Punt Adjacency
11 000010b = 194 = Incomplete Adjacency
11 000011b = 195 = For us

Examples:

  value : 0x40 = 64
  binary: 01000000
  decode: 01        -> Forward
            000000  -> No further information

  value : 0x89 = 137
  binary: 10001001
  decode: 10        -> Drop
            001001  -> Fragmentation and DF set
```"),
90 => (MplsVpnRouteDistinguisher, mpls_vpn_route_distinguisher, octetArray, (), doc="The value of the VPN route distinguisher of a corresponding
entry in a VPN routing and forwarding table.  Route
distinguisher ensures that the same address can be used in
several different MPLS VPNs and that it is possible for BGP to
carry several completely different routes to that address, one
for each VPN.  According to [RFC4364], the size of
mplsVpnRouteDistinguisher is 8 octets.  However, in [RFC4382] an
octet string with flexible length was chosen for representing a
VPN route distinguisher by object MplsL3VpnRouteDistinguisher.
This choice was made in order to be open to future changes of
the size.  This idea was adopted when choosing octetArray as
abstract data type for this Information Element.  The maximum
length of this Information Element is 256 octets."),
91 => (MplsTopLabelPrefixLength, mpls_top_label_prefix_length, u8, (), doc="The prefix length of the subnet of the mplsTopLabelIPv4Address that
the MPLS top label will cause the Flow to be forwarded to."),
92 => (SrcTrafficIndex, src_traffic_index, u32, (), doc="BGP Policy Accounting Source Traffic Index."),
93 => (DstTrafficIndex, dst_traffic_index, u32, (), doc="BGP Policy Accounting Destination Traffic Index."),
94 => (ApplicationDescription, application_description, string, (), doc="Specifies the description of an application."),
95 => (ApplicationId, application_id, octetArray, (), doc="Specifies an Application ID per [RFC6759]."),
96 => (ApplicationName, application_name, string, (), doc="Specifies the name of an application."),
98 => (PostIpDiffservCodepoint, post_ip_diffserv_codepoint, u8, (), doc="The definition of this Information Element is identical to the
definition of Information Element 'ipDiffServCodePoint', except
that it reports a potentially modified value caused by a
middlebox function after the packet passed the Observation
Point."),
99 => (MulticastReplicationFactor, multicast_replication_factor, u32, (), doc="The amount of multicast replication that's applied to a traffic
stream."),
100 => (ClassName, class_name, string, (), doc="Deprecated in favor of 335 selectorName.  Traffic Class Name,
associated with the classId Information Element."),
101 => (ClassificationEngineId, classification_engine_id, u8, (), doc="A unique identifier for the engine that determined the
Selector ID. Thus, the Classification Engine ID defines
the context for the Selector ID. The Classification
Engine can be considered a specific registry for
application assignments.




Values for this field are listed in the Classification
Engine IDs registry. See
[http://www.iana.org/assignments/ipfix/ipfix.xml#classification-engine-ids]"),
102 => (Layer2packetSectionOffset, layer2packet_section_offset, u16, (), doc="Deprecated in favor of 409 sectionOffset.  Layer 2 packet
section offset.  Potentially a generic packet section offset."),
103 => (Layer2packetSectionSize, layer2packet_section_size, u16, (), doc="Deprecated in favor of 312 dataLinkFrameSize.  Layer 2 packet
section size.  Potentially a generic packet section size."),
104 => (Layer2packetSectionData, layer2packet_section_data, octetArray, (), doc="Deprecated in favor of 315 dataLinkFrameSection.  Layer 2 packet
section data."),
128 => (BgpNextAdjacentAsNumber, bgp_next_adjacent_as_number, u32, (), doc="The autonomous system (AS) number of the first AS in the AS
path to the destination IP address.  The path is deduced
by looking up the destination IP address of the Flow in the
BGP routing information base.  If AS path information for
this Flow is only available as an unordered AS set (and not
as an ordered AS sequence), then the value of this Information
Element is 0."),
129 => (BgpPrevAdjacentAsNumber, bgp_prev_adjacent_as_number, u32, (), doc="The autonomous system (AS) number of the last AS in the AS
path from the source IP address.  The path is deduced
by looking up the source IP address of the Flow in the BGP
routing information base.  If AS path information for this
Flow is only available as an unordered AS set (and not as
an ordered AS sequence), then the value of this Information
Element is 0.  In case of BGP asymmetry, the
bgpPrevAdjacentAsNumber might not be able to report the correct
value."),
130 => (ExporterIpv4Address, exporter_ipv4_address, [u8; 4], (), doc="The IPv4 address used by the Exporting Process.  This is used
by the Collector to identify the Exporter in cases where the
identity of the Exporter may have been obscured by the use of
a proxy."),
131 => (ExporterIpv6Address, exporter_ipv6_address, [u8; 16], (), doc="The IPv6 address used by the Exporting Process.  This is used
by the Collector to identify the Exporter in cases where the
identity of the Exporter may have been obscured by the use of
a proxy."),
132 => (DroppedOctetDeltaCount, dropped_octet_delta_count, u64, (), doc="The number of octets since the previous report (if any)
in packets of this Flow dropped by packet treatment.
The number of octets includes IP header(s) and IP payload."),
133 => (DroppedPacketDeltaCount, dropped_packet_delta_count, u64, (), doc="The number of packets since the previous report (if any)
of this Flow dropped by packet treatment."),
134 => (DroppedOctetTotalCount, dropped_octet_total_count, u64, (), doc="The total number of octets in packets of this Flow dropped
by packet treatment since the Metering Process
(re-)initialization for this Observation Point.
The number of octets includes IP header(s) and IP payload."),
135 => (DroppedPacketTotalCount, dropped_packet_total_count, u64, (), doc="The number of packets of this Flow dropped by packet
treatment since the Metering Process
(re-)initialization for this Observation Point."),
136 => (FlowEndReason, flow_end_reason, u8, (), doc="The reason for Flow termination.  The range of values includes
the following:


```txt
0x01: idle timeout
The Flow was terminated because it was considered to be
idle.
0x02: active timeout
The Flow was terminated for reporting purposes while it was
still active, for example, after the maximum lifetime of
unreported Flows was reached.
0x03: end of Flow detected
The Flow was terminated because the Metering Process
detected signals indicating the end of the Flow,
for example, the TCP FIN flag.
0x04: forced end
The Flow was terminated because of some external event,
for example, a shutdown of the Metering Process initiated
by a network management application.
0x05: lack of resources
The Flow was terminated because of lack of resources
available to the Metering Process and/or the Exporting
Process.
```"),
137 => (CommonPropertiesId, common_properties_id, u64, (), doc="An identifier of a set of common properties that is
unique per Observation Domain and Transport Session.
Typically, this Information Element is used to link to
information reported in separate Data Records."),
138 => (ObservationPointId, observation_point_id, u64, (), doc="An identifier of an Observation Point that is unique per
Observation Domain.  It is RECOMMENDED that this identifier is
also unique per IPFIX Device.  Typically, this Information
Element is used for limiting the scope of other Information
Elements."),
139 => (IcmpTypeCodeIpv6, icmp_type_code_ipv6, u16, (), doc="Type and Code of the IPv6 ICMP message.  The combination of
both values is reported as (ICMP type * 256) + ICMP code."),
140 => (MplsTopLabelIpv6Address, mpls_top_label_ipv6_address, [u8; 16], (), doc="The IPv6 address of the system that the MPLS top label will
cause this Flow to be forwarded to."),
141 => (LineCardId, line_card_id, u32, (), doc="An identifier of a line card that is unique per IPFIX
Device hosting an Observation Point.  Typically, this
Information Element is used for limiting the scope
of other Information Elements."),
142 => (PortId, port_id, u32, (), doc="An identifier of a line port that is unique per IPFIX
Device hosting an Observation Point.  Typically, this
Information Element is used for limiting the scope
of other Information Elements."),
143 => (MeteringProcessId, metering_process_id, u32, (), doc="An identifier of a Metering Process that is unique per
IPFIX Device.  Typically, this Information Element is used
for limiting the scope of other Information Elements.
Note that process identifiers are typically assigned
dynamically.
The Metering Process may be re-started with a different ID."),
144 => (ExportingProcessId, exporting_process_id, u32, (), doc="An identifier of an Exporting Process that is unique per
IPFIX Device.  Typically, this Information Element is used
for limiting the scope of other Information Elements.
Note that process identifiers are typically assigned
dynamically.  The Exporting Process may be re-started
with a different ID."),
145 => (TemplateId, template_id, u16, (), doc="An identifier of a Template that is locally unique within a
combination of a Transport session and an Observation Domain.




Template IDs 0-255 are reserved for Template Sets, Options
Template Sets, and other reserved Sets yet to be created.
Template IDs of Data Sets are numbered from 256 to 65535.




Typically, this Information Element is used for limiting
the scope of other Information Elements.
Note that after a re-start of the Exporting Process Template
identifiers may be re-assigned."),
146 => (WlanChannelId, wlan_channel_id, u8, (), doc="The identifier of the 802.11 (Wi-Fi) channel used."),
147 => (WlanSSID, wlan_ssid, string, (), doc="The Service Set IDentifier (SSID) identifying an 802.11
(Wi-Fi) network used.  According to IEEE.802-11.1999, the
SSID is encoded into a string of up to 32 characters."),
148 => (FlowId, flow_id, u64, (), doc="An identifier of a Flow that is unique within an Observation
Domain.  This Information Element can be used to distinguish
between different Flows if Flow Keys such as IP addresses and
port numbers are not reported or are reported in separate
records."),
149 => (ObservationDomainId, observation_domain_id, u32, (), doc="An identifier of an Observation Domain that is locally
unique to an Exporting Process.  The Exporting Process uses
the Observation Domain ID to uniquely identify to the
Collecting Process the Observation Domain where Flows
were metered.  It is RECOMMENDED that this identifier is
also unique per IPFIX Device.




A value of 0 indicates that no specific Observation Domain
is identified by this Information Element.




Typically, this Information Element is used for limiting
the scope of other Information Elements."),
150 => (FlowStartSeconds, flow_start_seconds, u64, (4, 8), doc="The absolute timestamp of the first packet of this Flow."),
151 => (FlowEndSeconds, flow_end_seconds, u64, (4, 8), doc="The absolute timestamp of the last packet of this Flow."),
152 => (FlowStartMilliseconds, flow_start_milliseconds, u64, (4, 8), doc="The absolute timestamp of the first packet of this Flow."),
153 => (FlowEndMilliseconds, flow_end_milliseconds, u64, (4, 8), doc="The absolute timestamp of the last packet of this Flow."),
154 => (FlowStartMicroseconds, flow_start_microseconds, u64, (4, 8), doc="The absolute timestamp of the first packet of this Flow."),
155 => (FlowEndMicroseconds, flow_end_microseconds, u64, (4, 8), doc="The absolute timestamp of the last packet of this Flow."),
156 => (FlowStartNanoseconds, flow_start_nanoseconds, u64, (4, 8), doc="The absolute timestamp of the first packet of this Flow."),
157 => (FlowEndNanoseconds, flow_end_nanoseconds, u64, (4, 8), doc="The absolute timestamp of the last packet of this Flow."),
158 => (FlowStartDeltaMicroseconds, flow_start_delta_microseconds, u32, (), doc="This is a relative timestamp only valid within the scope
of a single IPFIX Message.  It contains the negative time
offset of the first observed packet of this Flow relative
to the export time specified in the IPFIX Message Header."),
159 => (FlowEndDeltaMicroseconds, flow_end_delta_microseconds, u32, (), doc="This is a relative timestamp only valid within the scope
of a single IPFIX Message.  It contains the negative time
offset of the last observed packet of this Flow relative
to the export time specified in the IPFIX Message Header."),
160 => (SystemInitTimeMilliseconds, system_init_time_milliseconds, u64, (4, 8), doc="The absolute timestamp of the last (re-)initialization of the
IPFIX Device."),
161 => (FlowDurationMilliseconds, flow_duration_milliseconds, u32, (), doc="The difference in time between the first observed packet
of this Flow and the last observed packet of this Flow."),
162 => (FlowDurationMicroseconds, flow_duration_microseconds, u32, (), doc="The difference in time between the first observed packet
of this Flow and the last observed packet of this Flow."),
163 => (ObservedFlowTotalCount, observed_flow_total_count, u64, (), doc="The total number of Flows observed in the Observation Domain
since the Metering Process (re-)initialization for this
Observation Point."),
164 => (IgnoredPacketTotalCount, ignored_packet_total_count, u64, (), doc="The total number of observed IP packets that the
Metering Process did not process since the
(re-)initialization of the Metering Process."),
165 => (IgnoredOctetTotalCount, ignored_octet_total_count, u64, (), doc="The total number of octets in observed IP packets
(including the IP header) that the Metering Process
did not process since the (re-)initialization of the
Metering Process."),
166 => (NotSentFlowTotalCount, not_sent_flow_total_count, u64, (), doc="The total number of Flow Records that were generated by the
Metering Process and dropped by the Metering Process or
by the Exporting Process instead of being sent to the
Collecting Process. There are several potential reasons for
this including resource shortage and special Flow export
policies."),
167 => (NotSentPacketTotalCount, not_sent_packet_total_count, u64, (), doc="The total number of packets in Flow Records that were
generated by the Metering Process and dropped
by the Metering Process or by the Exporting Process
instead of being sent to the Collecting Process.
There are several potential reasons for this including
resource shortage and special Flow export policies."),
168 => (NotSentOctetTotalCount, not_sent_octet_total_count, u64, (), doc="The total number of octets in packets in Flow Records
that were generated by the Metering Process and
dropped by the Metering Process or by the Exporting
Process instead of being sent to the Collecting Process.
There are several potential reasons for this including
resource shortage and special Flow export policies."),
169 => (DestinationIpv6Prefix, destination_ipv6_prefix, [u8; 16], (), doc="IPv6 destination address prefix."),
170 => (SourceIpv6Prefix, source_ipv6_prefix, [u8; 16], (), doc="IPv6 source address prefix."),
171 => (PostOctetTotalCount, post_octet_total_count, u64, (), doc="The definition of this Information Element is identical
to the definition of Information Element
'octetTotalCount', except that it reports a
potentially modified value caused by a middlebox
function after the packet passed the Observation Point."),
172 => (PostPacketTotalCount, post_packet_total_count, u64, (), doc="The definition of this Information Element is identical
to the definition of Information Element
'packetTotalCount', except that it reports a
potentially modified value caused by a middlebox
function after the packet passed the Observation Point."),
173 => (FlowKeyIndicator, flow_key_indicator, u64, (), doc="This set of bit fields is used for marking the Information
Elements of a Data Record that serve as Flow Key.  Each bit
represents an Information Element in the Data Record with
the n-th bit representing the n-th Information Element.
A bit set to value 1 indicates that the corresponding
Information Element is a Flow Key of the reported Flow.
A bit set to value 0 indicates that this is not the case.




If the Data Record contains more than 64 Information Elements,
the corresponding Template SHOULD be designed such that all
Flow Keys are among the first 64 Information Elements, because
the flowKeyIndicator only contains 64 bits.  If the Data Record
contains less than 64 Information Elements, then the bits in
the flowKeyIndicator for which no corresponding Information
Element exists MUST have the value 0."),
174 => (PostMcastPacketTotalCount, post_mcast_packet_total_count, u64, (), doc="The total number of outgoing multicast packets sent for
packets of this Flow by a multicast daemon within the
Observation Domain since the Metering Process
(re-)initialization.  This property cannot necessarily
be observed at the Observation Point, but may be retrieved
by other means."),
175 => (PostMcastOctetTotalCount, post_mcast_octet_total_count, u64, (), doc="The total number of octets in outgoing multicast packets
sent for packets of this Flow by a multicast daemon in the
Observation Domain since the Metering Process
(re-)initialization.  This property cannot necessarily be
observed at the Observation Point, but may be retrieved by
other means.
The number of octets includes IP header(s) and IP payload."),
176 => (IcmpTypeIpv4, icmp_type_ipv4, u8, (), doc="Type of the IPv4 ICMP message."),
177 => (IcmpCodeIpv4, icmp_code_ipv4, u8, (), doc="Code of the IPv4 ICMP message."),
178 => (IcmpTypeIpv6, icmp_type_ipv6, u8, (), doc="Type of the IPv6 ICMP message."),
179 => (IcmpCodeIpv6, icmp_code_ipv6, u8, (), doc="Code of the IPv6 ICMP message."),
180 => (UdpSourcePort, udp_source_port, u16, (), doc="The source port identifier in the UDP header."),
181 => (UdpDestinationPort, udp_destination_port, u16, (), doc="The destination port identifier in the UDP header."),
182 => (TcpSourcePort, tcp_source_port, u16, (), doc="The source port identifier in the TCP header."),
183 => (TcpDestinationPort, tcp_destination_port, u16, (), doc="The destination port identifier in the TCP header."),
184 => (TcpSequenceNumber, tcp_sequence_number, u32, (), doc="The sequence number in the TCP header."),
185 => (TcpAcknowledgementNumber, tcp_acknowledgement_number, u32, (), doc="The acknowledgement number in the TCP header."),
186 => (TcpWindowSize, tcp_window_size, u16, (), doc="The window field in the TCP header.
If the TCP window scale is supported,
then TCP window scale must be known
to fully interpret the value of this information."),
187 => (TcpUrgentPointer, tcp_urgent_pointer, u16, (), doc="The urgent pointer in the TCP header."),
188 => (TcpHeaderLength, tcp_header_length, u8, (), doc="The length of the TCP header.  Note that the value of this
Information Element is different from the value of the Data
Offset field in the TCP header.  The Data Offset field
indicates the length of the TCP header in units of 4 octets.
This Information Elements specifies the length of the TCP
header in units of octets."),
189 => (IpHeaderLength, ip_header_length, u8, (), doc="The length of the IP header.  For IPv6, the value of this
Information Element is 40."),
190 => (TotalLengthIpv4, total_length_ipv4, u16, (), doc="The total length of the IPv4 packet."),
191 => (PayloadLengthIpv6, payload_length_ipv6, u16, (), doc="This Information Element reports the value of the Payload
Length field in the IPv6 header.  Note that IPv6 extension
headers belong to the payload.  Also note that in case of a
jumbo payload option the value of the Payload Length field in
the IPv6 header is zero and so will be the value reported
by this Information Element."),
192 => (IpTTL, ip_ttl, u8, (), doc="For IPv4, the value of the Information Element matches
the value of the Time to Live (TTL) field in the IPv4 packet
header.  For IPv6, the value of the Information Element
matches the value of the Hop Limit field in the IPv6
packet header."),
193 => (NextHeaderIpv6, next_header_ipv6, u8, (), doc="The value of the Next Header field of the IPv6 header.
The value identifies the type of the following IPv6
extension header or of the following IP payload.
Valid values are defined in the IANA
Protocol Numbers registry."),
194 => (MplsPayloadLength, mpls_payload_length, u32, (), doc="The size of the MPLS packet without the label stack."),
195 => (IpDiffservCodepoint, ip_diffserv_codepoint, u8, (), doc="The value of a Differentiated Services Code Point (DSCP)
encoded in the Differentiated Services field.  The
Differentiated Services field spans the most significant
6 bits of the IPv4 TOS field or the IPv6 Traffic Class
field, respectively.




This Information Element encodes only the 6 bits of the
Differentiated Services field.  Therefore, its value may
range from 0 to 63."),
196 => (IpPrecedence, ip_precedence, u8, (), doc="The value of the IP Precedence.  The IP Precedence value
is encoded in the first 3 bits of the IPv4 TOS field
or the IPv6 Traffic Class field, respectively.




This Information Element encodes only these 3 bits.
Therefore, its value may range from 0 to 7."),
197 => (FragmentFlags, fragment_flags, u8, (), doc="Fragmentation properties indicated by flags in the IPv4
packet header or the IPv6 Fragment header, respectively.



```txt
Bit 0:    (RS) Reserved.
The value of this bit MUST be 0 until specified
otherwise.
Bit 1:    (DF) 0 = May Fragment,  1 = Don't Fragment.
Corresponds to the value of the DF flag in the
IPv4 header.  Will always be 0 for IPv6 unless
a \"don't fragment\" feature is introduced to IPv6.
Bit 2:    (MF) 0 = Last Fragment, 1 = More Fragments.
Corresponds to the MF flag in the IPv4 header
or to the M flag in the IPv6 Fragment header,
respectively.  The value is 0 for IPv6 if there
is no fragment header.
Bits 3-7: (DC) Don't Care.
The values of these bits are irrelevant.

0   1   2   3   4   5   6   7
+---+---+---+---+---+---+---+---+
| R | D | M | D | D | D | D | D |
| S | F | F | C | C | C | C | C |
+---+---+---+---+---+---+---+---+
```"),
198 => (OctetDeltaSumOfSquares, octet_delta_sum_of_squares, u64, (), doc="The sum of the squared numbers of octets per incoming
packet since the previous report (if any) for this
Flow at the Observation Point.
The number of octets includes IP header(s) and IP payload."),
199 => (OctetTotalSumOfSquares, octet_total_sum_of_squares, u64, (), doc="The total sum of the squared numbers of octets in incoming
packets for this Flow at the Observation Point since the
Metering Process (re-)initialization for this Observation
Point.  The number of octets includes IP header(s) and IP
payload."),
200 => (MplsTopLabelTTL, mpls_top_label_ttl, u8, (), doc="The TTL field from the top MPLS label stack entry,
i.e., the last label that was pushed."),
201 => (MplsLabelStackLength, mpls_label_stack_length, u32, (), doc="The length of the MPLS label stack in units of octets."),
202 => (MplsLabelStackDepth, mpls_label_stack_depth, u32, (), doc="The number of labels in the MPLS label stack."),
203 => (MplsTopLabelExp, mpls_top_label_exp, u8, (), doc="The Exp field from the top MPLS label stack entry,
i.e., the last label that was pushed.


```txt
Bits 0-4:  Don't Care, value is irrelevant.
Bits 5-7:  MPLS Exp field.

0   1   2   3   4   5   6   7
+---+---+---+---+---+---+---+---+
|     don't care    |    Exp    |
+---+---+---+---+---+---+---+---+
```"),
204 => (IpPayloadLength, ip_payload_length, u32, (), doc="The effective length of the IP payload.




For IPv4 packets, the value of this Information Element is
the difference between the total length of the IPv4 packet
(as reported by Information Element totalLengthIPv4) and the
length of the IPv4 header (as reported by Information Element
headerLengthIPv4).




For IPv6, the value of the Payload Length field
in the IPv6 header is reported except in the case that
the value of this field is zero and that there is a valid
jumbo payload option.  In this case, the value of the
Jumbo Payload Length field in the jumbo payload option
is reported."),
205 => (UdpMessageLength, udp_message_length, u16, (), doc="The value of the Length field in the UDP header."),
206 => (IsMulticast, is_multicast, u8, (), doc="If the IP destination address is not a reserved multicast
address, then the value of all bits of the octet (including
the reserved ones) is zero.




The first bit of this octet is set to 1 if the Version
field of the IP header has the value 4 and if the
Destination Address field contains a reserved multicast
address in the range from 224.0.0.0 to 239.255.255.255.
Otherwise, this bit is set to 0.




The second and third bits of this octet are reserved for
future use.




The remaining bits of the octet are only set to values
other than zero if the IP Destination Address is a
reserved IPv6 multicast address.  Then the fourth bit
of the octet is set to the value of the T flag in the
IPv6 multicast address and the remaining four bits are
set to the value of the scope field in the IPv6
multicast address.


```txt
0      1      2      3      4      5      6      7
+------+------+------+------+------+------+------+------+
|   IPv6 multicast scope    |  T   | RES. | RES. | MCv4 |
+------+------+------+------+------+------+------+------+

Bits 0-3:  set to value of multicast scope if IPv6 multicast
Bit  4:    set to value of T flag, if IPv6 multicast
Bits 5-6:  reserved for future use
Bit  7:    set to 1 if IPv4 multicast
```"),
207 => (Ipv4IHL, ipv4_ihl, u8, (), doc="The value of the Internet Header Length (IHL) field in
the IPv4 header.  It specifies the length of the header
in units of 4 octets.  Please note that its unit is
different from most of the other Information Elements
reporting length values."),
208 => (Ipv4Options, ipv4_options, u32, (), doc="IPv4 options in packets of this Flow.
The information is encoded in a set of bit fields.  For
each valid IPv4 option type, there is a bit in this set.
The bit is set to 1 if any observed packet of this Flow
contains the corresponding IPv4 option type.  Otherwise,
if no observed packet of this Flow contained the
respective IPv4 option type, the value of the
corresponding bit is 0.




The list of valid IPv4 options is maintained by IANA.
Note that for identifying an option not just the 5-bit
Option Number, but all 8 bits of the Option Type need to
match one of the IPv4 options specified at
http://www.iana.org/assignments/ip-parameters.




Options are mapped to bits according to their option numbers.
Option number X is mapped to bit X.
The mapping is illustrated by the figure below.


```txt
0      1      2      3      4      5      6      7
+------+------+------+------+------+------+------+------+
|  RR  |CIPSO |E-SEC |  TS  | LSR  |  SEC | NOP  | EOOL |
+------+------+------+------+------+------+------+------+

8      9     10     11     12     13     14     15
+------+------+------+------+------+------+------+------+
|ENCODE| VISA | FINN | MTUR | MTUP | ZSU  | SSR  | SID  | ...
+------+------+------+------+------+------+------+------+

16     17     18     19     20     21     22     23
+------+------+------+------+------+------+------+------+
| DPS  |NSAPA | SDB  |RTRALT|ADDEXT|  TR  | EIP  |IMITD | ...
+------+------+------+------+------+------+------+------+

24     25     26     27     28     29     30     31
+------+------+------+------+------+------+------+------+
|      | EXP  |   to be assigned by IANA  |  QS  | UMP  | ...
+------+------+------+------+------+------+------+------+

Type   Option
Bit Value  Name    Reference
---+-----+-------+------------------------------------
0     7   RR      Record Route, RFC 791
1   134   CIPSO   Commercial Security
2   133   E-SEC   Extended Security, RFC 1108
3    68   TS      Time Stamp, RFC 791
4   131   LSR     Loose Source Route, RFC791
5   130   SEC     Security, RFC 1108
6     1   NOP     No Operation, RFC 791
7     0   EOOL    End of Options List, RFC 791
8    15   ENCODE
9   142   VISA    Experimental Access Control
10   205   FINN    Experimental Flow Control
11    12   MTUR    (obsoleted) MTU Reply, RFC 1191
12    11   MTUP    (obsoleted) MTU Probe, RFC 1191
13    10   ZSU     Experimental Measurement
14   137   SSR     Strict Source Route, RFC 791
15   136   SID     Stream ID, RFC 791
16   151   DPS     Dynamic Packet State
17   150   NSAPA   NSAP Address
18   149   SDB     Selective Directed Broadcast
19   147   ADDEXT  Address Extension
20   148   RTRALT  Router Alert, RFC 2113
21    82   TR      Traceroute, RFC 3193
22   145   EIP     Extended Internet Protocol, RFC 1385
23   144   IMITD   IMI Traffic Descriptor
25    30   EXP     RFC3692-style Experiment
25    94   EXP     RFC3692-style Experiment
25   158   EXP     RFC3692-style Experiment
25   222   EXP     RFC3692-style Experiment
30    25   QS      Quick-Start
31   152   UMP     Upstream Multicast Pkt.
...  ...   ...     Further options numbers
may be assigned by IANA
```"),
209 => (TcpOptions, tcp_options, u64, (), doc="TCP options in packets of this Flow.
The information is encoded in a set of bit fields.  For
each TCP option, there is a bit in this set.
The bit is set to 1 if any observed packet of this Flow
contains the corresponding TCP option.
Otherwise, if no observed packet of this Flow contained
the respective TCP option, the value of the
corresponding bit is 0.




Options are mapped to bits according to their option
numbers.  Option number X is mapped to bit X.
TCP option numbers are maintained by IANA.


```txt
0     1     2     3     4     5     6     7
+-----+-----+-----+-----+-----+-----+-----+-----+
|   7 |   6 |   5 |   4 |   3 |   2 |   1 |   0 |  ...
+-----+-----+-----+-----+-----+-----+-----+-----+

8     9    10    11    12    13    14    15
+-----+-----+-----+-----+-----+-----+-----+-----+
|  15 |  14 |  13 |  12 |  11 |  10 |   9 |   8 |...
+-----+-----+-----+-----+-----+-----+-----+-----+

16    17    18    19    20    21    22    23
+-----+-----+-----+-----+-----+-----+-----+-----+
|  23 |  22 |  21 |  20 |  19 |  18 |  17 |  16 |...
+-----+-----+-----+-----+-----+-----+-----+-----+

. . .

56    57    58    59    60    61    62    63
+-----+-----+-----+-----+-----+-----+-----+-----+
|  63 |  62 |  61 |  60 |  59 |  58 |  57 |  56 |
+-----+-----+-----+-----+-----+-----+-----+-----+
```"),
210 => (PaddingOctets, padding_octets, octetArray, (), doc="The value of this Information Element is always a sequence of
0x00 values."),
211 => (CollectorIpv4Address, collector_ipv4_address, [u8; 4], (), doc="An IPv4 address to which the Exporting Process sends Flow
information."),
212 => (CollectorIpv6Address, collector_ipv6_address, [u8; 16], (), doc="An IPv6 address to which the Exporting Process sends Flow
information."),
213 => (ExportInterface, export_interface, u32, (), doc="The index of the interface from which IPFIX Messages sent
by the Exporting Process to a Collector leave the IPFIX
Device.  The value matches the value of
managed object 'ifIndex' as defined in [RFC2863].
Note that ifIndex values are not assigned statically to an
interface and that the interfaces may be renumbered every
time the device's management system is re-initialized, as
specified in [RFC2863]."),
214 => (ExportProtocolVersion, export_protocol_version, u8, (), doc="The protocol version used by the Exporting Process for
sending Flow information.  The protocol version is given
by the value of the Version Number field in the Message
Header.




The protocol version is 10 for IPFIX and 9 for NetFlow
version 9.
A value of 0 indicates that no export protocol is in use."),
215 => (ExportTransportProtocol, export_transport_protocol, u8, (), doc="The value of the protocol number used by the Exporting Process
for sending Flow information.
The protocol number identifies the IP packet payload type.
Protocol numbers are defined in the IANA Protocol Numbers
registry.




In Internet Protocol version 4 (IPv4), this is carried in the
Protocol field.  In Internet Protocol version 6 (IPv6), this
is carried in the Next Header field in the last extension
header of the packet."),
216 => (CollectorTransportPort, collector_transport_port, u16, (), doc="The destination port identifier to which the Exporting
Process sends Flow information.  For the transport protocols
UDP, TCP, and SCTP, this is the destination port number.
This field MAY also be used for future transport protocols
that have 16-bit source port identifiers."),
217 => (ExporterTransportPort, exporter_transport_port, u16, (), doc="The source port identifier from which the Exporting
Process sends Flow information.  For the transport protocols
UDP, TCP, and SCTP, this is the source port number.
This field MAY also be used for future transport protocols
that have 16-bit source port identifiers.  This field may
be useful for distinguishing multiple Exporting Processes
that use the same IP address."),
218 => (TcpSynTotalCount, tcp_syn_total_count, u64, (), doc="The total number of packets of this Flow with
TCP \"Synchronize sequence numbers\" (SYN) flag set."),
219 => (TcpFinTotalCount, tcp_fin_total_count, u64, (), doc="The total number of packets of this Flow with
TCP \"No more data from sender\" (FIN) flag set."),
220 => (TcpRstTotalCount, tcp_rst_total_count, u64, (), doc="The total number of packets of this Flow with
TCP \"Reset the connection\" (RST) flag set."),
221 => (TcpPshTotalCount, tcp_psh_total_count, u64, (), doc="The total number of packets of this Flow with
TCP \"Push Function\" (PSH) flag set."),
222 => (TcpAckTotalCount, tcp_ack_total_count, u64, (), doc="The total number of packets of this Flow with
TCP \"Acknowledgment field significant\" (ACK) flag set."),
223 => (TcpUrgTotalCount, tcp_urg_total_count, u64, (), doc="The total number of packets of this Flow with
TCP \"Urgent Pointer field significant\" (URG) flag set."),
224 => (IpTotalLength, ip_total_length, u64, (), doc="The total length of the IP packet."),
225 => (PostNATSourceIpv4Address, post_nat_source_ipv4_address, [u8; 4], (), doc="The definition of this Information Element is identical to the
definition of Information Element 'sourceIPv4Address', except
that it reports a modified value caused by a NAT middlebox
function after the packet passed the Observation Point."),
226 => (PostNATDestinationIpv4Address, post_nat_destination_ipv4_address, [u8; 4], (), doc="The definition of this Information Element is identical to the
definition of Information Element 'destinationIPv4Address',
except that it reports a modified value caused by a NAT
middlebox function after the packet passed the Observation
Point."),
227 => (PostNAPTSourceTransportPort, post_napt_source_transport_port, u16, (), doc="The definition of this Information Element is identical to the
definition of Information Element 'sourceTransportPort', except
that it reports a modified value caused by a Network Address
Port Translation (NAPT) middlebox function after the packet
passed the Observation Point."),
228 => (PostNAPTDestinationTransportPort, post_napt_destination_transport_port, u16, (), doc="The definition of this Information Element is identical to the
definition of Information Element 'destinationTransportPort',
except that it reports a modified value caused by a Network
Address Port Translation (NAPT) middlebox function after the
packet passed the Observation Point."),
229 => (NatOriginatingAddressRealm, nat_originating_address_realm, u8, (), doc="Indicates whether the session was created because traffic
originated in the private or public address realm.
postNATSourceIPv4Address, postNATDestinationIPv4Address,
postNAPTSourceTransportPort, and
postNAPTDestinationTransportPort are qualified with the address
realm in perspective.




The allowed values are:




Private: 1




Public:  2"),
230 => (NatEvent, nat_event, u8, (), doc="Indicates a NAT event. The allowed values are:




1 - Create event.




2 - Delete event.




3 - Pool exhausted.




A Create event is generated when a NAT translation is created,
whether dynamically or statically.  A Delete event is generated
when a NAT translation is deleted."),
231 => (InitiatorOctets, initiator_octets, u64, (), doc="The total number of layer 4 payload bytes in a flow from the
initiator.  The initiator is the device which triggered the
session creation, and remains the same for the life of the
session."),
232 => (ResponderOctets, responder_octets, u64, (), doc="The total number of layer 4 payload bytes in a flow from the
responder.  The responder is the device which replies to the
initiator, and remains the same for the life of the session."),
233 => (FirewallEvent, firewall_event, u8, (), doc="Indicates a firewall event.  The allowed values are:




0 - Ignore (invalid)




1 - Flow Created




2 - Flow Deleted




3 - Flow Denied




4 - Flow Alert




5 - Flow Update"),
234 => (IngressVRFID, ingress_vrfid, u32, (), doc="An unique identifier of the VRFname where the packets of this
flow are being received.  This identifier is unique per Metering
Process"),
235 => (EgressVRFID, egress_vrfid, u32, (), doc="An unique identifier of the VRFname where the packets of this
flow are being sent.  This identifier is unique per Metering
Process"),
236 => (VRFname, vr_fname, string, (), doc="The name of a VPN Routing and Forwarding table (VRF)."),
237 => (PostMplsTopLabelExp, post_mpls_top_label_exp, u8, (), doc="The definition of this Information Element is identical to the
definition of Information Element 'mplsTopLabelExp', except
that it reports a potentially modified value caused by a
middlebox function after the packet passed the Observation
Point."),
238 => (TcpWindowScale, tcp_window_scale, u16, (), doc="The scale of the window field in the TCP header."),
239 => (BiflowDirection, biflow_direction, u8, (), doc="A description of the direction assignment method used to
assign the Biflow Source and Destination.  This Information Element
MAY be present in a Flow Data Record, or applied to all flows exported
from an Exporting Process or Observation Domain using IPFIX Options.
If this Information Element is not present in a Flow Record or
associated with a Biflow via scope, it is assumed that the
configuration of the direction assignment method is done out-of-band.
Note that when using IPFIX Options to apply this Information Element
to all flows within an Observation Domain or from an Exporting
Process, the Option SHOULD be sent reliably.  If reliable transport is
not available (i.e., when using UDP), this Information Element SHOULD
appear in each Flow Record.  This field may take the following
values:

```txt
+-------+------------------+----------------------------------------+
| Value | Name             | Description                            |
+-------+------------------+----------------------------------------+
| 0x00  | arbitrary        | Direction was assigned arbitrarily.    |
| 0x01  | initiator        | The Biflow Source is the flow          |
|       |                  | initiator, as determined by the        |
|       |                  | Metering Process' best effort to       |
|       |                  | detect the initiator.                  |
| 0x02  | reverseInitiator | The Biflow Destination is the flow     |
|       |                  | initiator, as determined by the        |
|       |                  | Metering Process' best effort to       |
|       |                  | detect the initiator.  This value is   |
|       |                  | provided for the convenience of        |
|       |                  | Exporting Processes to revise an       |
|       |                  | initiator estimate without re-encoding |
|       |                  | the Biflow Record.                     |
| 0x03  | perimeter        | The Biflow Source is the endpoint      |
|       |                  | outside of a defined perimeter.  The   |
|       |                  | perimeter's definition is implicit in  |
|       |                  | the set of Biflow Source and Biflow    |
|       |                  | Destination addresses exported in the  |
|       |                  | Biflow Records.                        |
+-------+------------------+----------------------------------------+
```"),
240 => (EthernetHeaderLength, ethernet_header_length, u8, (), doc="The difference between the length of an Ethernet frame (minus the
FCS) and the length of its MAC Client Data section (including any
padding) as defined in section 3.1 of [IEEE.802-3.2005].  It does
not include the Preamble, SFD and Extension field lengths."),
241 => (EthernetPayloadLength, ethernet_payload_length, u16, (), doc="The length of the MAC Client Data section (including any padding)
of a frame as defined in section 3.1 of [IEEE.802-3.2005]."),
242 => (EthernetTotalLength, ethernet_total_length, u16, (), doc="The total length of the Ethernet frame (excluding the Preamble,
SFD, Extension and FCS fields) as described in section 3.1 of
[IEEE.802-3.2005]."),
243 => (Dot1qVlanId, dot1q_vlan_id, u16, (), doc="The value of the 12-bit VLAN Identifier portion of the Tag Control
Information field of an Ethernet frame.  The structure and
semantics within the Tag Control Information field are defined in
[IEEE802.1Q].  In Provider Bridged Networks, it represents the
Service VLAN identifier in the Service VLAN Tag (S-TAG) Tag
Control Information (TCI) field or the Customer VLAN identifier in
the Customer VLAN Tag (C-TAG) Tag Control Information (TCI) field
as described in [IEEE802.1Q].  In Provider Backbone Bridged
Networks, it represents the Backbone VLAN identifier in the
Backbone VLAN Tag (B-TAG) Tag Control Information (TCI) field as
described in [IEEE802.1Q].  In a virtual link between a host
system and EVB bridge, it represents the Service VLAN identifier
indicating S-channel as described in [IEEE802.1Qbg].




In the case of a multi-tagged frame, it represents the outer tag's
VLAN identifier, except for I-TAG."),
244 => (Dot1qPriority, dot1q_priority, u8, (), doc="The value of the 3-bit User Priority portion of the Tag Control
Information field of an Ethernet frame.  The structure and
semantics within the Tag Control Information field are defined in
[IEEE802.1Q].  In the case of multi-tagged frame, it represents
the 3-bit Priority Code Point (PCP) portion of the outer tag's Tag
Control Information (TCI) field as described in [IEEE802.1Q],
except for I-TAG."),
245 => (Dot1qCustomerVlanId, dot1q_customer_vlan_id, u16, (), doc="The value represents the Customer VLAN identifier in the Customer
VLAN Tag (C-TAG) Tag Control Information (TCI) field as described
in [IEEE802.1Q]."),
246 => (Dot1qCustomerPriority, dot1q_customer_priority, u8, (), doc="The value represents the 3-bit Priority Code Point (PCP) portion
of the Customer VLAN Tag (C-TAG) Tag Control Information (TCI)
field as described in [IEEE802.1Q]."),
247 => (MetroEvcId, metro_evc_id, string, (), doc="The EVC Service Attribute which uniquely identifies the Ethernet
Virtual Connection (EVC) within a Metro Ethernet Network, as
defined in section 6.2 of MEF 10.1.  The MetroEVCID is encoded in
a string of up to 100 characters."),
248 => (MetroEvcType, metro_evc_type, u8, (), doc="The 3-bit EVC Service Attribute which identifies the type of
service provided by an EVC."),
249 => (PseudoWireId, pseudo_wire_id, u32, (), doc="A 32-bit non-zero connection identifier, which together with the
pseudoWireType, identifies the Pseudo Wire (PW) as defined in [RFC4447]."),
250 => (PseudoWireType, pseudo_wire_type, u16, (), doc="The value of this information element identifies the type of MPLS
Pseudo Wire (PW) as defined in [RFC4446]."),
251 => (PseudoWireControlWord, pseudo_wire_control_word, u32, (), doc="The 32-bit Preferred Pseudo Wire (PW) MPLS Control Word as
defined in Section 3 of [RFC4385]."),
252 => (IngressPhysicalInterface, ingress_physical_interface, u32, (), doc="The index of a networking device's physical interface (example, a
switch port) where packets of this flow are being received."),
253 => (EgressPhysicalInterface, egress_physical_interface, u32, (), doc="The index of a networking device's physical interface (example, a
switch port) where packets of this flow are being sent."),
254 => (PostDot1qVlanId, post_dot1q_vlan_id, u16, (), doc="The definition of this Information Element is identical to the
definition of Information Element 'dot1qVlanId', except that it
reports a potentially modified value caused by a middlebox
function after the packet passed the Observation Point."),
255 => (PostDot1qCustomerVlanId, post_dot1q_customer_vlan_id, u16, (), doc="The definition of this Information Element is identical to the
definition of Information Element 'dot1qCustomerVlanId', except
that it reports a potentially modified value caused by a
middlebox function after the packet passed the Observation Point."),
256 => (EthernetType, ethernet_type, u16, (), doc="The Ethernet type field of an Ethernet frame that identifies the
MAC client protocol carried in the payload as defined in
paragraph 1.4.349 of [IEEE.802-3.2005]."),
257 => (PostIpPrecedence, post_ip_precedence, u8, (), doc="The definition of this Information Element is identical to the
definition of Information Element 'ipPrecedence', except that
it reports a potentially modified value caused by a middlebox
function after the packet passed the Observation Point."),
258 => (CollectionTimeMilliseconds, collection_time_milliseconds, u64, (4, 8), doc="The absolute timestamp at which the data within the
scope containing this Information Element was received by a
Collecting Process.  This Information Element SHOULD be bound to
its containing IPFIX Message via IPFIX Options and the
messageScope Information Element, as defined below."),
259 => (ExportSctpStreamId, export_sctp_stream_id, u16, (), doc="The value of the SCTP Stream Identifier used by the
Exporting Process for exporting IPFIX Message data.  This is
carried in the Stream Identifier field of the header of the SCTP
DATA chunk containing the IPFIX Message(s)."),
260 => (MaxExportSeconds, max_export_seconds, u64, (4, 8), doc="The absolute Export Time of the latest IPFIX Message
within the scope containing this Information Element. This
Information Element SHOULD be bound to its containing IPFIX
Transport Session via IPFIX Options and the sessionScope
Information Element."),
261 => (MaxFlowEndSeconds, max_flow_end_seconds, u64, (4, 8), doc="The latest absolute timestamp of the last packet
within any Flow within the scope containing this Information
Element, rounded up to the second if necessary.  This Information
Element SHOULD be bound to its containing IPFIX Transport Session
via IPFIX Options and the sessionScope Information Element."),
262 => (MessageMD5Checksum, message_md5_checksum, octetArray, (), doc="The MD5 checksum of the IPFIX Message containing this
record.  This Information Element SHOULD be bound to its
containing IPFIX Message via an options record and the
messageScope Information Element, as defined below, and SHOULD
appear only once in a given IPFIX Message.  To calculate the value
of this Information Element, first buffer the containing IPFIX
Message, setting the value of this Information Element to all
zeroes.  Then calculate the MD5 checksum of the resulting buffer
as defined in [RFC1321], place the resulting value in this
Information Element, and export the buffered message.  This
Information Element is intended as a simple checksum only;
therefore collision resistance and algorithm agility are not
required, and MD5 is an appropriate message digest.

This Information Element has a fixed length of 16 octets."),
263 => (MessageScope, message_scope, u8, (), doc="The presence of this Information Element as scope in
an Options Template signifies that the options described by the
Template apply to the IPFIX Message that contains them. It is
defined for general purpose message scoping of options, and
proposed specifically to allow the attachment a checksum to a
message via IPFIX Options. The value of this Information Element
MUST be written as 0 by the File Writer or Exporting Process. The
value of this Information Element MUST be ignored by the File
Reader or the Collecting Process."),
264 => (MinExportSeconds, min_export_seconds, u64, (4, 8), doc="The absolute Export Time of the earliest IPFIX Message
within the scope containing this Information Element.  This
Information Element SHOULD be bound to its containing IPFIX
Transport Session via an options record and the sessionScope
Information Element."),
265 => (MinFlowStartSeconds, min_flow_start_seconds, u64, (4, 8), doc="The earliest absolute timestamp of the first packet
within any Flow within the scope containing this Information
Element, rounded down to the second if necessary.  This
Information Element SHOULD be bound to its containing IPFIX
Transport Session via an options record and the sessionScope
Information Element."),
266 => (OpaqueOctets, opaque_octets, octetArray, (), doc="This Information Element is used to encapsulate non-
IPFIX data into an IPFIX Message stream, for the purpose of
allowing a non-IPFIX data processor to store a data stream inline
within an IPFIX File.  A Collecting Process or File Writer MUST
NOT try to interpret this binary data.  This Information Element
differs from paddingOctets as its contents are meaningful in some
non-IPFIX context, while the contents of paddingOctets MUST be
0x00 and are intended only for Information Element alignment."),
267 => (SessionScope, session_scope, u8, (), doc="The presence of this Information Element as scope in
an Options Template signifies that the options described by the
Template apply to the IPFIX Transport Session that contains them.
Note that as all options are implicitly scoped to Transport
Session and Observation Domain, this Information Element is
equivalent to a \"null\" scope.  It is defined for general purpose
session scoping of options, and proposed specifically to allow the
attachment of time window to an IPFIX File via IPFIX Options.  The
value of this Information Element MUST be written as 0 by the File
Writer or Exporting Process.  The value of this Information
Element MUST be ignored by the File Reader or the Collecting
Process."),
268 => (MaxFlowEndMicroseconds, max_flow_end_microseconds, u64, (4, 8), doc="The latest absolute timestamp of the last packet
within any Flow within the scope containing this Information
Element, rounded up to the microsecond if necessary.  This
Information Element SHOULD be bound to its containing IPFIX
Transport Session via IPFIX Options and the sessionScope
Information Element.  This Information Element SHOULD be used only
in Transport Sessions containing Flow Records with microsecond-
precision (or better) timestamp Information Elements."),
269 => (MaxFlowEndMilliseconds, max_flow_end_milliseconds, u64, (4, 8), doc="The latest absolute timestamp of the last packet
within any Flow within the scope containing this Information
Element, rounded up to the millisecond if necessary.  This
Information Element SHOULD be bound to its containing IPFIX
Transport Session via IPFIX Options and the sessionScope
Information Element.  This Information Element SHOULD be used only
in Transport Sessions containing Flow Records with millisecond-
precision (or better) timestamp Information Elements."),
270 => (MaxFlowEndNanoseconds, max_flow_end_nanoseconds, u64, (4, 8), doc="The latest absolute timestamp of the last packet
within any Flow within the scope containing this Information
Element.  This Information Element SHOULD be bound to its
containing IPFIX Transport Session via IPFIX Options and the
sessionScope Information Element.  This Information Element SHOULD
be used only in Transport Sessions containing Flow Records with
nanosecond-precision timestamp Information Elements."),
271 => (MinFlowStartMicroseconds, min_flow_start_microseconds, u64, (4, 8), doc="The earliest absolute timestamp of the first packet
within any Flow within the scope containing this Information
Element, rounded down to the microsecond if necessary.  This
Information Element SHOULD be bound to its containing IPFIX
Transport Session via an options record and the sessionScope
Information Element.  This Information Element SHOULD be used only
in Transport Sessions containing Flow Records with microsecond-
precision (or better) timestamp Information Elements."),
272 => (MinFlowStartMilliseconds, min_flow_start_milliseconds, u64, (4, 8), doc="The earliest absolute timestamp of the first packet
within any Flow within the scope containing this Information
Element, rounded down to the millisecond if necessary.  This
Information Element SHOULD be bound to its containing IPFIX
Transport Session via an options record and the sessionScope
Information Element.  This Information Element SHOULD be used only
in Transport Sessions containing Flow Records with millisecond-
precision (or better) timestamp Information Elements."),
273 => (MinFlowStartNanoseconds, min_flow_start_nanoseconds, u64, (4, 8), doc="The earliest absolute timestamp of the first packet
within any Flow within the scope containing this Information
Element.  This Information Element SHOULD be bound to its
containing IPFIX Transport Session via an options record and the
sessionScope Information Element.  This Information Element SHOULD
be used only in Transport Sessions containing Flow Records with
nanosecond-precision timestamp Information Elements."),
274 => (CollectorCertificate, collector_certificate, octetArray, (), doc="The full X.509 certificate, encoded in ASN.1 DER
format, used by the Collector when IPFIX Messages were transmitted
using TLS or DTLS.  This Information Element SHOULD be bound to
its containing IPFIX Transport Session via an options record and
the sessionScope Information Element, or to its containing IPFIX
Message via an options record and the messageScope Information
Element."),
275 => (ExporterCertificate, exporter_certificate, octetArray, (), doc="The full X.509 certificate, encoded in ASN.1 DER
format, used by the Collector when IPFIX Messages were transmitted
using TLS or DTLS.  This Information Element SHOULD be bound to
its containing IPFIX Transport Session via an options record and
the sessionScope Information Element, or to its containing IPFIX
Message via an options record and the messageScope Information
Element."),
276 => (DataRecordsReliability, data_records_reliability, bool, (), doc="The export reliability of Data Records, within this SCTP
stream, for the element(s) in the Options Template
scope.  A typical example of an element for which the
export reliability will be reported is the templateID,
as specified in the Data Records Reliability Options
Template.  A value of 'True' means that the Exporting
Process MUST send any Data Records associated with the
element(s) reliably within this SCTP stream.  A value of
'False' means that the Exporting Process MAY send any
Data Records associated with the element(s) unreliably
within this SCTP stream."),
277 => (ObservationPointType, observation_point_type, u8, (), doc="Type of observation point. Values assigned to date are:




1. Physical port




2. Port channel




3. Vlan."),
278 => (NewConnectionDeltaCount, new_connection_delta_count, u32, (), doc="This information element counts the number of TCP or UDP
connections which were opened during the observation period. The
observation period may be specified by the flow start and end timestamps."),
279 => (ConnectionSumDurationSeconds, connection_sum_duration_seconds, u64, (), doc="This information element aggregates the total time in
seconds for all of the TCP or UDP connections which were in use during
the observation period. For example if there are 5 concurrent
connections each for 10 seconds, the value would be 50 s."),
280 => (ConnectionTransactionId, connection_transaction_id, u64, (), doc="This information element identifies a transaction within a
connection. A transaction is a meaningful exchange of application data
between two network devices or a client and server. A transactionId is
assigned the first time a flow is reported, so that later reports for
the same flow will have the same transactionId. A different
transactionId is used for each transaction within a TCP or UDP
connection. The identifiers need not be sequential."),
281 => (PostNATSourceIpv6Address, post_nat_source_ipv6_address, [u8; 16], (), doc="The definition of this Information Element is identical to
the definition of Information Element 'sourceIPv6Address', except that
it reports a modified value caused by a NAT64 middlebox function after
the packet passed the Observation Point.

See [RFC2460] for the definition of the Source Address field in the IPv6
header. See [RFC3234] for the definition of middleboxes. See
[RFC6146] for nat64 specification."),
282 => (PostNATDestinationIpv6Address, post_nat_destination_ipv6_address, [u8; 16], (), doc="The definition of this Information Element is identical to
the definition of Information Element 'destinationIPv6Address', except
that it reports a modified value caused by a NAT64 middlebox function
after the packet passed the Observation Point.

See [RFC2460] for the definition of the Destination Address field in the
IPv6 header. See [RFC3234] for the definition of middleboxes. See
[RFC6146] for nat64 specification."),
283 => (NatPoolId, nat_pool_id, u32, (), doc="Locally unique identifier of a NAT pool."),
284 => (NatPoolName, nat_pool_name, string, (), doc="The name of a NAT pool identified by a natPoolID."),
285 => (AnonymizationFlags, anonymization_flags, u16, (), doc="A flag word describing specialized modifications to
the anonymization policy in effect for the anonymization technique
applied to a referenced Information Element within a referenced
Template.  When flags are clear (0), the normal policy (as
described by anonymizationTechnique) applies without modification.


```txt
MSB   14  13  12  11  10   9   8   7   6   5   4   3   2   1  LSB
+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
|                Reserved                       |LOR|PmA|   SC  |
+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+

anonymizationFlags IE

+--------+----------+-----------------------------------------------+
| bit(s) | name     | description                                   |
| (LSB = |          |                                               |
| 0)     |          |                                               |
+--------+----------+-----------------------------------------------+
| 0-1    | SC       | Stability Class: see the Stability Class      |
|        |          | table below, and section Section 5.1.         |
| 2      | PmA      | Perimeter Anonymization: when set (1),        |
|        |          | source- Information Elements as described in  |
|        |          | [RFC5103] are interpreted as external         |
|        |          | addresses, and destination- Information       |
|        |          | Elements as described in [RFC5103] are        |
|        |          | interpreted as internal addresses, for the    |
|        |          | purposes of associating                       |
|        |          | anonymizationTechnique to Information         |
|        |          | Elements only; see Section 7.2.2 for details. |
|        |          | This bit MUST NOT be set when associated with |
|        |          | a non-endpoint (i.e., source- or              |
|        |          | destination-) Information Element.  SHOULD be |
|        |          | consistent within a record (i.e., if a        |
|        |          | source- Information Element has this flag     |
|        |          | set, the corresponding destination- element   |
|        |          | SHOULD have this flag set, and vice-versa.)   |
| 3      | LOR      | Low-Order Unchanged: when set (1), the        |
|        |          | low-order bits of the anonymized Information  |
|        |          | Element contain real data.  This modification |
|        |          | is intended for the anonymization of          |
|        |          | network-level addresses while leaving         |
|        |          | host-level addresses intact in order to       |
|        |          | preserve host level-structure, which could    |
|        |          | otherwise be used to reverse anonymization.   |
|        |          | MUST NOT be set when associated with a        |
|        |          | truncation-based anonymizationTechnique.      |
| 4-15   | Reserved | Reserved for future use: SHOULD be cleared    |
|        |          | (0) by the Exporting Process and MUST be      |
|        |          | ignored by the Collecting Process.            |
+--------+----------+-----------------------------------------------+
```


The Stability Class portion of this flags word describes the
stability class of the anonymization technique applied to a
referenced Information Element within a referenced Template.
Stability classes refer to the stability of the parameters of the
anonymization technique, and therefore the comparability of the
mapping between the real and anonymized values over time.  This
determines which anonymized datasets may be compared with each
other.  Values are as follows:


```txt
+-----+-----+-------------------------------------------------------+
| Bit | Bit | Description                                           |
| 1   | 0   |                                                       |
+-----+-----+-------------------------------------------------------+
| 0   | 0   | Undefined: the Exporting Process makes no             |
|     |     | representation as to how stable the mapping is, or    |
|     |     | over what time period values of this field will       |
|     |     | remain comparable; while the Collecting Process MAY   |
|     |     | assume Session level stability, Session level         |
|     |     | stability is not guaranteed.  Processes SHOULD assume |
|     |     | this is the case in the absence of stability class    |
|     |     | information; this is the default stability class.     |
| 0   | 1   | Session: the Exporting Process will ensure that the   |
|     |     | parameters of the anonymization technique are stable  |
|     |     | during the Transport Session.  All the values of the  |
|     |     | described Information Element for each Record         |
|     |     | described by the referenced Template within the       |
|     |     | Transport Session are comparable.  The Exporting      |
|     |     | Process SHOULD endeavour to ensure at least this      |
|     |     | stability class.                                      |
| 1   | 0   | Exporter-Collector Pair: the Exporting Process will   |
|     |     | ensure that the parameters of the anonymization       |
|     |     | technique are stable across Transport Sessions over   |
|     |     | time with the given Collecting Process, but may use   |
|     |     | different parameters for different Collecting         |
|     |     | Processes.  Data exported to different Collecting     |
|     |     | Processes are not comparable.                         |
| 1   | 1   | Stable: the Exporting Process will ensure that the    |
|     |     | parameters of the anonymization technique are stable  |
|     |     | across Transport Sessions over time, regardless of    |
|     |     | the Collecting Process to which it is sent.           |
+-----+-----+-------------------------------------------------------+
```"),
286 => (AnonymizationTechnique, anonymization_technique, u16, (), doc="A description of the anonymization technique applied
to a referenced Information Element within a referenced Template.
Each technique may be applicable only to certain Information
Elements and recommended only for certain Infomation Elements;
these restrictions are noted in the table below.


```txt
+-------+---------------------------+-----------------+-------------+
| Value | Description               | Applicable to   | Recommended |
|       |                           |                 | for         |
+-------+---------------------------+-----------------+-------------+
| 0     | Undefined: the Exporting  | all             | all         |
|       | Process makes no          |                 |             |
|       | representation as to      |                 |             |
|       | whether the defined field |                 |             |
|       | is anonymized or not.     |                 |             |
|       | While the Collecting      |                 |             |
|       | Process MAY assume that   |                 |             |
|       | the field is not          |                 |             |
|       | anonymized, it is not     |                 |             |
|       | guaranteed not to be.     |                 |             |
|       | This is the default       |                 |             |
|       | anonymization technique.  |                 |             |
| 1     | None: the values exported | all             | all         |
|       | are real.                 |                 |             |
| 2     | Precision                 | all             | all         |
|       | Degradation/Truncation:   |                 |             |
|       | the values exported are   |                 |             |
|       | anonymized using simple   |                 |             |
|       | precision degradation or  |                 |             |
|       | truncation.  The new      |                 |             |
|       | precision or number of    |                 |             |
|       | truncated bits is         |                 |             |
|       | implicit in the exported  |                 |             |
|       | data, and can be deduced  |                 |             |
|       | by the Collecting         |                 |             |
|       | Process.                  |                 |             |
| 3     | Binning: the values       | all             | all         |
|       | exported are anonymized   |                 |             |
|       | into bins.                |                 |             |
| 4     | Enumeration: the values   | all             | timestamps  |
|       | exported are anonymized   |                 |             |
|       | by enumeration.           |                 |             |
| 5     | Permutation: the values   | all             | identifiers |
|       | exported are anonymized   |                 |             |
|       | by permutation.           |                 |             |
| 6     | Structured Permutation:   | addresses       |             |
|       | the values exported are   |                 |             |
|       | anonymized by             |                 |             |
|       | permutation, preserving   |                 |             |
|       | bit-level structure as    |                 |             |
|       | appropriate; this         |                 |             |
|       | represents                |                 |             |
|       | prefix-preserving IP      |                 |             |
|       | address anonymization or  |                 |             |
|       | structured MAC address    |                 |             |
|       | anonymization.            |                 |             |
| 7     | Reverse Truncation: the   | addresses       |             |
|       | values exported are       |                 |             |
|       | anonymized using reverse  |                 |             |
|       | truncation.  The number   |                 |             |
|       | of truncated bits is      |                 |             |
|       | implicit in the exported  |                 |             |
|       | data, and can be deduced  |                 |             |
|       | by the Collecting         |                 |             |
|       | Process.                  |                 |             |
| 8     | Noise: the values         | non-identifiers | counters    |
|       | exported are anonymized   |                 |             |
|       | by adding random noise to |                 |             |
|       | each value.               |                 |             |
| 9     | Offset: the values        | all             | timestamps  |
|       | exported are anonymized   |                 |             |
|       | by adding a single offset |                 |             |
|       | to all values.            |                 |             |
+-------+---------------------------+-----------------+-------------+
```"),
287 => (InformationElementIndex, information_element_index, u16, (), doc="A zero-based index of an Information Element
referenced by informationElementId within a Template referenced by
templateId; used to disambiguate scope for templates containing
multiple identical Information Elements."),
288 => (P2pTechnology, p2p_technology, string, (), doc="Specifies if the Application ID is based on peer-to-peer
technology.




Possible values are: { \"yes\", \"y\", 1 },
{ \"no\", \"n\", 2 } and { \"unassigned\", \"u\", 0 }."),
289 => (TunnelTechnology, tunnel_technology, string, (), doc="Specifies if the Application ID is used as a tunnel technology.




Possible values are: { \"yes\", \"y\", 1 }, { \"no\", \"n\", 2 } and
{ \"unassigned\", \"u\", 0 }."),
290 => (EncryptedTechnology, encrypted_technology, string, (), doc="Specifies if the Application ID is an encrypted networking
protocol.
Possible values are: { \"yes\", \"y\", 1 },
{ \"no\", \"n\", 2 } and { \"unassigned\", \"u\", 0 }."),
291 => (BasicList, basic_list, basicList, (), doc="Specifies a generic Information Element with a basicList abstract
data type.  For example, a list of port numbers, a list of
interface indexes, etc."),
292 => (SubTemplateList, sub_template_list, subTemplateList, (), doc="Specifies a generic Information Element with a subTemplateList
abstract data type."),
293 => (SubTemplateMultiList, sub_template_multi_list, subTemplateMultiList, (), doc="Specifies a generic Information Element with a
subTemplateMultiList abstract data type."),
294 => (BgpValidityState, bgp_validity_state, u8, (), doc="This element describes the \"validity state\" of the BGP route correspondent source or destination IP address. If the \"validity state\" for this Flow is only available, then the value of this Information Element is 255."),
295 => (IPSecSPI, ip_sec_spi, u32, (), doc="IPSec Security Parameters Index (SPI)."),
296 => (GreKey, gre_key, u32, (), doc="GRE key, which is used for identifying an individual traffic flow within a tunnel."),
297 => (NatType, nat_type, u8, (), doc="The type of NAT treatment:




0 unknown




1 NAT44 translated




2 NAT64 translated




3 NAT46 translated




4 IPv4-->IPv4 (no NAT)




5 NAT66 translated




6 IPv6-->IPv6 (no NAT)"),
298 => (InitiatorPackets, initiator_packets, u64, (), doc="The total number of layer 4 packets in a flow from the
initiator. The initiator is the device which triggered the
session creation, and remains the same for the life of the
session."),
299 => (ResponderPackets, responder_packets, u64, (), doc="The total number of layer 4 packets in a flow from the
responder. The responder is the device which replies to the
initiator, and remains the same for the life of the session."),
300 => (ObservationDomainName, observation_domain_name, string, (), doc="The name of an observation domain identified by an
observationDomainId."),
301 => (SelectionSequenceId, selection_sequence_id, u64, (), doc="From all the packets observed at an Observation Point, a subset of
the packets is selected by a sequence of one or more Selectors.
The selectionSequenceId is a unique value per Observation Domain,
specifying the Observation Point and the sequence of Selectors
through which the packets are selected."),
302 => (SelectorId, selector_id, u64, (), doc="The Selector ID is the unique ID identifying a Primitive Selector.
Each Primitive Selector must have a unique ID in the Observation
Domain."),
303 => (InformationElementId, information_element_id, u16, (), doc="This Information Element contains the ID of another Information
Element."),
304 => (SelectorAlgorithm, selector_algorithm, u16, (), doc="This Information Element identifies the packet selection methods
(e.g., Filtering, Sampling) that are applied by the Selection
Process.




Most of these methods have parameters.  Further Information
Elements are needed to fully specify packet selection with these
methods and all their parameters.




The methods listed below are defined in [RFC5475].  For their parameters, Information Elements are defined in
the information model document.  The names of these Information
Elements are listed for each method identifier.




Further method identifiers may be added to the list below.  It
might be necessary to define new Information Elements to specify
their parameters.




The selectorAlgorithm registry is maintained by IANA.  New
assignments for the registry will be administered by IANA, and
are subject to Expert Review [RFC5226].




The registry can be updated when specifications of the new
method(s) and any new Information Elements are provided.




The group of experts must double check the selectorAlgorithm
definitions and Information Elements with already defined
selectorAlgorithms and Information Elements for completeness,
accuracy, and redundancy.  Those experts will initially be drawn
from the Working Group Chairs and document editors of the IPFIX
and PSAMP Working Groups.




The following packet selection methods identifiers are defined
here:




[IANA registry psamp-parameters]




There is a broad variety of possible parameters that could be used
for Property match Filtering (5) but currently there are no agreed
parameters specified."),
305 => (SamplingPacketInterval, sampling_packet_interval, u32, (), doc="This Information Element specifies the number of packets that are
consecutively sampled.  A value of 100 means that 100
consecutive packets are sampled.




For example, this Information Element may be used to describe the
configuration of a systematic count-based Sampling Selector."),
306 => (SamplingPacketSpace, sampling_packet_space, u32, (), doc="This Information Element specifies the number of packets between
two \"samplingPacketInterval\"s.  A value of 100 means that the next
interval starts 100 packets (which are not sampled) after the
current \"samplingPacketInterval\" is over.




For example, this Information Element may be used to describe the
configuration of a systematic count-based Sampling Selector."),
307 => (SamplingTimeInterval, sampling_time_interval, u32, (), doc="This Information Element specifies the time interval in
microseconds during which all arriving packets are sampled.




For example, this Information Element may be used to describe the
configuration of a systematic time-based Sampling Selector."),
308 => (SamplingTimeSpace, sampling_time_space, u32, (), doc="This Information Element specifies the time interval in
microseconds between two \"samplingTimeInterval\"s.  A value of 100
means that the next interval starts 100 microseconds (during which
no packets are sampled) after the current \"samplingTimeInterval\"
is over.




For example, this Information Element may used to describe the
configuration of a systematic time-based Sampling Selector."),
309 => (SamplingSize, sampling_size, u32, (), doc="This Information Element specifies the number of elements taken
from the parent Population for random Sampling methods.




For example, this Information Element may be used to describe the
configuration of a random n-out-of-N Sampling Selector."),
310 => (SamplingPopulation, sampling_population, u32, (), doc="This Information Element specifies the number of elements in the
parent Population for random Sampling methods.




For example, this Information Element may be used to describe the
configuration of a random n-out-of-N Sampling Selector."),
311 => (SamplingProbability, sampling_probability, f64, (), doc="This Information Element specifies the probability that a packet
is sampled, expressed as a value between 0 and 1.  The probability
is equal for every packet.  A value of 0 means no packet was
sampled since the probability is 0.




For example, this Information Element may be used to describe the
configuration of a uniform probabilistic Sampling Selector."),
312 => (DataLinkFrameSize, data_link_frame_size, u16, (), doc="This Information Element specifies the length of the selected data
link frame.




The data link layer is defined in [ISO/IEC.7498-1:1994]."),
313 => (IpHeaderPacketSection, ip_header_packet_section, octetArray, (), doc="This Information Element carries a series of n octets from the IP
header of a sampled packet, starting sectionOffset octets into the
IP header.




However, if no sectionOffset field corresponding to this
Information Element is present, then a sectionOffset of zero
applies, and the octets MUST be from the start of the IP header.




With sufficient length, this element also reports octets from the
IP payload.  However, full packet capture of arbitrary packet
streams is explicitly out of scope per the Security Considerations
sections of [RFC5477] and [RFC2804].




The sectionExportedOctets expresses how much data was exported,
while the remainder is padding.




When the sectionExportedOctets field corresponding to this
Information Element exists, this Information Element MAY have a
fixed length and MAY be padded, or it MAY have a variable length.




When the sectionExportedOctets field corresponding to this
Information Element does not exist, this Information Element
SHOULD have a variable length and MUST NOT be padded.  In this
case, the size of the exported section may be constrained due to
limitations in the IPFIX protocol."),
314 => (IpPayloadPacketSection, ip_payload_packet_section, octetArray, (), doc="This Information Element carries a series of n octets from the IP
payload of a sampled packet, starting sectionOffset octets into
the IP payload.




However, if no sectionOffset field corresponding to this
Information Element is present, then a sectionOffset of zero
applies, and the octets MUST be from the start of the IP payload.




The IPv4 payload is that part of the packet that follows the IPv4
header and any options, which [RFC791] refers to as \"data\" or
\"data octets\".  For example, see the examples in [RFC791],
Appendix A.




The IPv6 payload is the rest of the packet following the 40-octet
IPv6 header.  Note that any extension headers present are
considered part of the payload.  See [RFC2460] for the IPv6
specification.




The sectionExportedOctets expresses how much data was observed,
while the remainder is padding.




When the sectionExportedOctets field corresponding to this
Information Element exists, this Information Element MAY have a
fixed length and MAY be padded, or MAY have a variable length.




When the sectionExportedOctets field corresponding to this
Information Element does not exist, this Information Element
SHOULD have a variable length and MUST NOT be padded.  In this
case, the size of the exported section may be constrained due to
limitations in the IPFIX protocol."),
315 => (DataLinkFrameSection, data_link_frame_section, octetArray, (), doc="This Information Element carries n octets from the data link frame
of a selected frame, starting sectionOffset octets into the frame.




However, if no sectionOffset field corresponding to this
Information Element is present, then a sectionOffset of zero
applies, and the octets MUST be from the start of the data link
frame.




The sectionExportedOctets expresses how much data was observed,
while the remainder is padding.




When the sectionExportedOctets field corresponding to this
Information Element exists, this Information Element MAY have a
fixed length and MAY be padded, or MAY have a variable length.




When the sectionExportedOctets field corresponding to this
Information Element does not exist, this Information Element
SHOULD have a variable length and MUST NOT be padded.  In this
case, the size of the exported section may be constrained due to
limitations in the IPFIX protocol.




Further Information Elements, i.e., dataLinkFrameType and
dataLinkFrameSize, are needed to specify the data link type and the
size of the data link frame of this Information Element.  A set of
these Information Elements MAY be contained in a structured data
type, as expressed in [RFC6313].  Or a set of these Information
Elements MAY be contained in one Flow Record as shown in Appendix
B of [RFC7133].




The data link layer is defined in [ISO/IEC.7498-1:1994]."),
316 => (MplsLabelStackSection, mpls_label_stack_section, octetArray, (), doc="This Information Element carries a series of n octets from the
MPLS label stack of a sampled packet, starting sectionOffset
octets into the MPLS label stack.




However, if no sectionOffset field corresponding to this
Information Element is present, then a sectionOffset of zero
applies, and the octets MUST be from the head of the MPLS label
stack.




With sufficient length, this element also reports octets from the
MPLS payload.  However, full packet capture of arbitrary packet
streams is explicitly out of scope per the Security Considerations
sections of [RFC5477] and [RFC2804].




See [RFC3031] for the specification of MPLS packets.




See [RFC3032] for the specification of the MPLS label stack.




The sectionExportedOctets expresses how much data was observed,
while the remainder is padding.




When the sectionExportedOctets field corresponding to this
Information Element exists, this Information Element MAY have a
fixed length and MAY be padded, or MAY have a variable length.




When the sectionExportedOctets field corresponding to this
Information Element does not exist, this Information Element
SHOULD have a variable length and MUST NOT be padded.  In this
case, the size of the exported section may be constrained due to
limitations in the IPFIX protocol."),
317 => (MplsPayloadPacketSection, mpls_payload_packet_section, octetArray, (), doc="The mplsPayloadPacketSection carries a series of n octets from the
MPLS payload of a sampled packet, starting sectionOffset octets
into the MPLS payload, as it is data that follows immediately after
the MPLS label stack.




However, if no sectionOffset field corresponding to this
Information Element is present, then a sectionOffset of zero
applies, and the octets MUST be from the start of the MPLS
payload.




See [RFC3031] for the specification of MPLS packets.




See [RFC3032] for the specification of the MPLS label stack.




The sectionExportedOctets expresses how much data was observed,
while the remainder is padding.




When the sectionExportedOctets field corresponding to this
Information Element exists, this Information Element MAY have a
fixed length and MAY be padded, or it MAY have a variable length.




When the sectionExportedOctets field corresponding to this
Information Element does not exist, this Information Element
SHOULD have a variable length and MUST NOT be padded.  In this
case, the size of the exported section may be constrained due to
limitations in the IPFIX protocol."),
318 => (SelectorIdTotalPktsObserved, selector_id_total_pkts_observed, u64, (), doc="This Information Element specifies the total number of packets
observed by a Selector, for a specific value of SelectorId.




This Information Element should be used in an Options Template
scoped to the observation to which it refers.  See Section 3.4.2.1
of the IPFIX protocol document [RFC7011]."),
319 => (SelectorIdTotalPktsSelected, selector_id_total_pkts_selected, u64, (), doc="This Information Element specifies the total number of packets
selected by a Selector, for a specific value of SelectorId.




This Information Element should be used in an Options Template
scoped to the observation to which it refers.  See Section 3.4.2.1
of the IPFIX protocol document [RFC7011]."),
320 => (AbsoluteError, absolute_error, f64, (), doc="This Information Element specifies the maximum possible
measurement error of the reported value for a given Information
Element.  The absoluteError has the same unit as the Information
Element with which it is associated.  The real value of the metric can
differ by absoluteError (positive or negative) from the measured
value.




This Information Element provides only the error for measured
values.  If an Information Element contains an estimated value
(from Sampling), the confidence boundaries and confidence level
have to be provided instead, using the upperCILimit, lowerCILimit,
and confidenceLevel Information Elements.




This Information Element should be used in an Options Template
scoped to the observation to which it refers.  See Section 3.4.2.1
of the IPFIX protocol document [RFC7011]."),
321 => (RelativeError, relative_error, f64, (), doc="This Information Element specifies the maximum possible positive
or negative error ratio for the reported value for a given
Information Element as percentage of the measured value.  The real
value of the metric can differ by relativeError percent (positive
or negative) from the measured value.




This Information Element provides only the error for measured
values.  If an Information Element contains an estimated value
(from Sampling), the confidence boundaries and confidence level
have to be provided instead, using the upperCILimit, lowerCILimit,
and confidenceLevel Information Elements.




This Information Element should be used in an Options Template
scoped to the observation to which it refers.  See Section 3.4.2.1
of the IPFIX protocol document [RFC7011]."),
322 => (ObservationTimeSeconds, observation_time_seconds, u64, (4, 8), doc="This Information Element specifies the absolute time in seconds of
an observation."),
323 => (ObservationTimeMilliseconds, observation_time_milliseconds, u64, (4, 8), doc="This Information Element specifies the absolute time in
milliseconds of an observation."),
324 => (ObservationTimeMicroseconds, observation_time_microseconds, u64, (4, 8), doc="This Information Element specifies the absolute time in
microseconds of an observation."),
325 => (ObservationTimeNanoseconds, observation_time_nanoseconds, u64, (4, 8), doc="This Information Element specifies the absolute time in
nanoseconds of an observation."),
326 => (DigestHashValue, digest_hash_value, u64, (), doc="This Information Element specifies the value from the digest hash
function.

See also Sections 6.2, 3.8 and 7.1 of [RFC5475]."),
327 => (HashIpPayloadOffset, hash_ip_payload_offset, u64, (), doc="This Information Element specifies the IP payload offset used by a
Hash-based Selection Selector.

See also Sections 6.2, 3.8 and 7.1 of [RFC5475]."),
328 => (HashIpPayloadSize, hash_ip_payload_size, u64, (), doc="This Information Element specifies the IP payload size used by a
Hash-based Selection Selector.  See also Sections 6.2, 3.8 and 7.1 of
[RFC5475]."),
329 => (HashOutputRangeMin, hash_output_range_min, u64, (), doc="This Information Element specifies the value for the beginning of
a hash function's potential output range.




See also Sections 6.2, 3.8 and 7.1 of [RFC5475]."),
330 => (HashOutputRangeMax, hash_output_range_max, u64, (), doc="This Information Element specifies the value for the end of a hash
function's potential output range.




See also Sections 6.2, 3.8 and 7.1 of [RFC5475]."),
331 => (HashSelectedRangeMin, hash_selected_range_min, u64, (), doc="This Information Element specifies the value for the beginning of
a hash function's selected range.




See also Sections 6.2, 3.8 and 7.1 of [RFC5475]."),
332 => (HashSelectedRangeMax, hash_selected_range_max, u64, (), doc="This Information Element specifies the value for the end of a hash
function's selected range.




See also Sections 6.2, 3.8 and 7.1 of [RFC5475]."),
333 => (HashDigestOutput, hash_digest_output, bool, (), doc="This Information Element contains a boolean value that is TRUE if
the output from this hash Selector has been configured to be
included in the packet report as a packet digest, else FALSE.




See also Sections 6.2, 3.8 and 7.1 of [RFC5475]."),
334 => (HashInitialiserValue, hash_initialiser_value, u64, (), doc="This Information Element specifies the initialiser value to the
hash function.




See also Sections 6.2, 3.8 and 7.1 of [RFC5475]."),
335 => (SelectorName, selector_name, string, (), doc="The name of a selector identified by a selectorID.  Globally
unique per Metering Process."),
336 => (UpperCILimit, upper_ci_limit, f64, (), doc="This Information Element specifies the upper limit of a confidence
interval.  It is used to provide an accuracy statement for an
estimated value.  The confidence limits define the range in which
the real value is assumed to be with a certain probability p.
Confidence limits always need to be associated with a confidence
level that defines this probability p.  Please note that a
confidence interval only provides a probability that the real
value lies within the limits.  That means the real value can lie
outside the confidence limits.




The upperCILimit, lowerCILimit, and confidenceLevel Information
Elements should all be used in an Options Template scoped to the
observation to which they refer.  See Section 3.4.2.1 of the IPFIX
protocol document [RFC7011].




Note that the upperCILimit, lowerCILimit, and confidenceLevel are
all required to specify confidence, and should be disregarded
unless all three are specified together."),
337 => (LowerCILimit, lower_ci_limit, f64, (), doc="This Information Element specifies the lower limit of a confidence
interval.  For further information, see the description of
upperCILimit.




The upperCILimit, lowerCILimit, and confidenceLevel Information
Elements should all be used in an Options Template scoped to the
observation to which they refer.  See Section 3.4.2.1 of the IPFIX
protocol document [RFC7011].




Note that the upperCILimit, lowerCILimit, and confidenceLevel are
all required to specify confidence, and should be disregarded
unless all three are specified together."),
338 => (ConfidenceLevel, confidence_level, f64, (), doc="This Information Element specifies the confidence level.  It is
used to provide an accuracy statement for estimated values.  The
confidence level provides the probability p with which the real
value lies within a given range.  A confidence level always needs
to be associated with confidence limits that define the range in
which the real value is assumed to be.




The upperCILimit, lowerCILimit, and confidenceLevel Information
Elements should all be used in an Options Template scoped to the
observation to which they refer.  See Section 3.4.2.1 of the IPFIX
protocol document [RFC7011].




Note that the upperCILimit, lowerCILimit, and confidenceLevel are
all required to specify confidence, and should be disregarded
unless all three are specified together."),
339 => (InformationElementDataType, information_element_data_type, u8, (), doc="A description of the abstract data type of an IPFIX
information element.These are taken from the abstract data types
defined in section 3.1 of the IPFIX Information Model [RFC5102];
see that section for more information on the types described
in the informationElementDataType sub-registry.




These types are registered in the IANA IPFIX Information Element
Data Type subregistry.  This subregistry is intended to assign
numbers for type names, not to provide a mechanism for adding data
types to the IPFIX Protocol, and as such requires a Standards
Action [RFC5226] to modify."),
340 => (InformationElementDescription, information_element_description, string, (), doc="A UTF-8 [RFC3629] encoded Unicode string containing a
human-readable description of an Information Element.  The content
of the informationElementDescription MAY be annotated with one or
more language tags [RFC4646], encoded in-line [RFC2482] within the
UTF-8 string, in order to specify the language in which the
description is written.  Description text in multiple languages
MAY tag each section with its own language tag; in this case, the
description information in each language SHOULD have equivalent
meaning.  In the absence of any language tag, the \"i-default\"
[RFC2277] language SHOULD be assumed.  See the Security
Considerations section for notes on string handling for
Information Element type records."),
341 => (InformationElementName, information_element_name, string, (), doc="A UTF-8 [RFC3629] encoded Unicode string containing
the name of an Information Element, intended as a simple
identifier.  See the Security Considerations section for notes on
string handling for Information Element type records"),
342 => (InformationElementRangeBegin, information_element_range_begin, u64, (), doc="Contains the inclusive low end of the range of
acceptable values for an Information Element."),
343 => (InformationElementRangeEnd, information_element_range_end, u64, (), doc="Contains the inclusive high end of the range of
acceptable values for an Information Element."),
344 => (InformationElementSemantics, information_element_semantics, u8, (), doc="A description of the semantics of an IPFIX Information
Element.  These are taken from the data type semantics defined in
section 3.2 of the IPFIX Information Model [RFC5102]; see that
section for more information on the types defined in the informationElementSemantics sub-registry.  This
field may take the values in Table ; the special value 0x00
(default) is used to note that no semantics apply to the field; it
cannot be manipulated by a Collecting Process or File Reader that
does not understand it a priori.




These semantics are registered in the IANA IPFIX Information
Element Semantics subregistry.  This subregistry is intended to
assign numbers for semantics names, not to provide a mechanism for
adding semantics to the IPFIX Protocol, and as such requires a
Standards Action [RFC5226] to modify."),
345 => (InformationElementUnits, information_element_units, u16, (), doc="A description of the units of an IPFIX Information
Element.  These correspond to the units implicitly defined in the
Information Element definitions in section 5 of the IPFIX
Information Model [RFC5102]; see that section for more information
on the types described in the informationElementsUnits sub-registry.  This field may take the values in
Table 3 below; the special value 0x00 (none) is used to note that
the field is unitless.




These types are registered in the IANA IPFIX Information Element
Units subregistry; new types may be added on a First Come First
Served [RFC5226] basis."),
346 => (PrivateEnterpriseNumber, private_enterprise_number, u32, (), doc="A private enterprise number, as assigned by IANA.
Within the context of an Information Element Type record, this
element can be used along with the informationElementId element to
scope properties to a specific Information Element.  To export
type information about an IANA-assigned Information Element, set
the privateEnterpriseNumber to 0, or do not export the
privateEnterpriseNumber in the type record.  To export type
information about an enterprise-specific Information Element,
export the enterprise number in privateEnterpriseNumber, and
export the Information Element number with the Enterprise bit
cleared in informationElementId.  The Enterprise bit in the
associated informationElementId Information Element MUST be
ignored by the Collecting Process."),
347 => (VirtualStationInterfaceId, virtual_station_interface_id, octetArray, (), doc="Instance Identifier of the interface to a Virtual Station. A Virtual
Station is an end station instance: it can be a virtual machine or a
physical host."),
348 => (VirtualStationInterfaceName, virtual_station_interface_name, string, (), doc="Name of the interface to a Virtual Station. A Virtual Station is an end station
instance: it can be a virtual machine or a physical host."),
349 => (VirtualStationUUID, virtual_station_uuid, octetArray, (), doc="Unique Identifier of a Virtual Station. A Virtual Station is an end station
instance: it can be a virtual machine or a physical host."),
350 => (VirtualStationName, virtual_station_name, string, (), doc="Name of a Virtual Station. A Virtual Station is an end station
instance: it can be a virtual machine or a physical host."),
351 => (Layer2SegmentId, layer2_segment_id, u64, (), doc="Identifier of a layer 2 network segment in an overlay network.
The most significant byte identifies the layer 2 network
overlay network encapsulation type:




0x00 reserved




0x01 VxLAN




0x02 NVGRE




The three lowest significant bytes
hold the value of the layer 2
overlay network segment identifier.




For example:




- a 24 bit segment ID VXLAN Network
Identifier (VNI)




- a 24 bit Tenant Network Identifier
(TNI) for NVGRE"),
352 => (Layer2OctetDeltaCount, layer2_octet_delta_count, u64, (), doc="The number of layer 2 octets since the previous report (if any) in
incoming packets for this Flow at the Observation Point.  The
number of octets includes layer 2 header(s) and layer 2 payload.
# memo: layer 2 version of octetDeltaCount (field #1)"),
353 => (Layer2OctetTotalCount, layer2_octet_total_count, u64, (), doc="The total number of layer 2 octets in incoming packets for this
Flow at the Observation Point since the Metering Process
(re-)initialization for this Observation Point.  The number of
octets includes layer 2 header(s) and layer 2 payload.
# memo: layer 2 version of octetTotalCount (field #85)"),
354 => (IngressUnicastPacketTotalCount, ingress_unicast_packet_total_count, u64, (), doc="The total number of incoming unicast packets metered at the
Observation Point since the Metering Process (re-)initialization
for this Observation Point."),
355 => (IngressMulticastPacketTotalCount, ingress_multicast_packet_total_count, u64, (), doc="The total number of incoming multicast packets metered at the
Observation Point since the Metering Process (re-)initialization
for this Observation Point."),
356 => (IngressBroadcastPacketTotalCount, ingress_broadcast_packet_total_count, u64, (), doc="The total number of incoming broadcast packets metered at the
Observation Point since the Metering Process (re-)initialization
for this Observation Point."),
357 => (EgressUnicastPacketTotalCount, egress_unicast_packet_total_count, u64, (), doc="The total number of incoming unicast packets metered at the
Observation Point since the Metering Process (re-)initialization
for this Observation Point."),
358 => (EgressBroadcastPacketTotalCount, egress_broadcast_packet_total_count, u64, (), doc="The total number of incoming broadcast packets metered at the
Observation Point since the Metering Process (re-)initialization
for this Observation Point."),
359 => (MonitoringIntervalStartMilliseconds, monitoring_interval_start_milliseconds, u64, (4, 8), doc="The absolute timestamp at which the monitoring interval
started.
A Monitoring interval is the period of time during which the Metering
Process is running."),
360 => (MonitoringIntervalEndMilliseconds, monitoring_interval_end_milliseconds, u64, (4, 8), doc="The absolute timestamp at which the monitoring interval ended.
A Monitoring interval is the period of time during which the Metering
Process is running."),
361 => (PortRangeStart, port_range_start, u16, (), doc="The port number identifying the start of a range of ports. A value
of zero indicates that the range start is not specified, ie the
range is defined in some other way.




Additional information on defined TCP port numbers can be found at
[IANA registry service-names-port-numbers]."),
362 => (PortRangeEnd, port_range_end, u16, (), doc="The port number identifying the end of a range of ports. A value
of zero indicates that the range end is not specified, ie the
range is defined in some other way.




Additional information on defined TCP port numbers can be found at
[IANA registry service-names-port-numbers]."),
363 => (PortRangeStepSize, port_range_step_size, u16, (), doc="The step size in a port range. The default step size is 1,
which indicates contiguous ports. A value of zero indicates
that the step size is not specified, ie the range is defined
in some other way."),
364 => (PortRangeNumPorts, port_range_num_ports, u16, (), doc="The number of ports in a port range. A value of zero indicates
that the number of ports is not specified, ie the range is defined
in some other way."),
365 => (StaMacAddress, sta_mac_address, [u8;6], (), doc="The IEEE 802 MAC address of a wireless station (STA)."),
366 => (StaIpv4Address, sta_ipv4_address, [u8; 4], (), doc="The IPv4 address of a wireless station (STA)."),
367 => (WtpMacAddress, wtp_mac_address, [u8;6], (), doc="The IEEE 802 MAC address of a wireless access point (WTP)."),
368 => (IngressInterfaceType, ingress_interface_type, u32, (), doc="The type of interface where packets of this Flow are being received.
The value matches the value of managed object 'ifType' as defined in
[IANA registry ianaiftype-mib]."),
369 => (EgressInterfaceType, egress_interface_type, u32, (), doc="The type of interface where packets of this Flow are being sent.
The value matches the value of managed object 'ifType' as defined in
[IANA registry ianaiftype-mib]."),
370 => (RtpSequenceNumber, rtp_sequence_number, u16, (), doc="The RTP sequence number per [RFC3550]."),
371 => (UserName, user_name, string, (), doc="User name associated with the flow."),
372 => (ApplicationCategoryName, application_category_name, string, (), doc="An attribute that provides a first level categorization for
each Application ID."),
373 => (ApplicationSubCategoryName, application_sub_category_name, string, (), doc="An attribute that provides a second level categorization
for each Application ID."),
374 => (ApplicationGroupName, application_group_name, string, (), doc="An attribute that groups multiple Application IDs that
belong to the same networking application."),
375 => (OriginalFlowsPresent, original_flows_present, u64, (), doc="The non-conservative count of Original Flows
contributing to this Aggregated Flow.  Non-conservative counts
need not sum to the original count on re-aggregation."),
376 => (OriginalFlowsInitiated, original_flows_initiated, u64, (), doc="The conservative count of Original Flows whose first
packet is represented within this Aggregated Flow.  Conservative
counts must sum to the original count on re-aggregation."),
377 => (OriginalFlowsCompleted, original_flows_completed, u64, (), doc="The conservative count of Original Flows whose last
packet is represented within this Aggregated Flow.  Conservative
counts must sum to the original count on re-aggregation."),
378 => (DistinctCountOfSourceIPAddress, distinct_count_of_source_ip_address, u64, (), doc="The count of distinct source IP address values for
Original Flows contributing to this Aggregated Flow, without
regard to IP version.  This Information Element is preferred to
the IP-version-specific counters, unless it is important to
separate the counts by version."),
379 => (DistinctCountOfDestinationIPAddress, distinct_count_of_destination_ip_address, u64, (), doc="The count of distinct destination IP address values
for Original Flows contributing to this Aggregated Flow, without
regard to IP version.  This Information Element is preferred to
the version-specific counters below, unless it is important to
separate the counts by version."),
380 => (DistinctCountOfSourceIpv4Address, distinct_count_of_source_ipv4_address, u32, (), doc="The count of distinct source IPv4 address values for
Original Flows contributing to this Aggregated Flow."),
381 => (DistinctCountOfDestinationIpv4Address, distinct_count_of_destination_ipv4_address, u32, (), doc="The count of distinct destination IPv4 address values
for Original Flows contributing to this Aggregated Flow."),
382 => (DistinctCountOfSourceIpv6Address, distinct_count_of_source_ipv6_address, u64, (), doc="The count of distinct source IPv6 address values for
Original Flows contributing to this Aggregated Flow."),
383 => (DistinctCountOfDestinationIpv6Address, distinct_count_of_destination_ipv6_address, u64, (), doc="The count of distinct destination IPv6 address values
for Original Flows contributing to this Aggregated Flow."),
384 => (ValueDistributionMethod, value_distribution_method, u8, (), doc="A description of the method used to distribute the
counters from Contributing Flows into the Aggregated Flow records
described by an associated scope, generally a Template.  The
method is deemed to apply to all the non-key Information Elements
in the referenced scope for which value distribution is a valid
operation; if the originalFlowsInitiated and/or
originalFlowsCompleted Information Elements appear in the
Template, they are not subject to this distribution method, as
they each infer their own distribution method.  This is intended
to be a complete set of possible value distribution methods; it is
encoded as follows:


```txt
+-------+-----------------------------------------------------------+
| Value | Description                                               |
+-------+-----------------------------------------------------------+
| 0     | Unspecified: The counters for an Original Flow are        |
|       | explicitly not distributed according to any other method  |
|       | defined for this Information Element; use for arbitrary   |
|       | distribution, or distribution algorithms not described by |
|       | any other codepoint.                                      |
|       | --------------------------------------------------------- |
|       |                                                           |
| 1     | Start Interval: The counters for an Original Flow are     |
|       | added to the counters of the appropriate Aggregated Flow  |
|       | containing the start time of the Original Flow.  This     |
|       | should be assumed the default if value distribution       |
|       | information is not available at a Collecting Process for  |
|       | an Aggregated Flow.                                       |
|       | --------------------------------------------------------- |
|       |                                                           |
| 2     | End Interval: The counters for an Original Flow are added |
|       | to the counters of the appropriate Aggregated Flow        |
|       | containing the end time of the Original Flow.             |
|       | --------------------------------------------------------- |
|       |                                                           |
| 3     | Mid Interval: The counters for an Original Flow are added |
|       | to the counters of a single appropriate Aggregated Flow   |
|       | containing some timestamp between start and end time of   |
|       | the Original Flow.                                        |
|       | --------------------------------------------------------- |
|       |                                                           |
| 4     | Simple Uniform Distribution: Each counter for an Original |
|       | Flow is divided by the number of time intervals the       |
|       | Original Flow covers (i.e., of appropriate Aggregated     |
|       | Flows sharing the same Flow Key), and this number is      |
|       | added to each corresponding counter in each Aggregated    |
|       | Flow.                                                     |
|       | --------------------------------------------------------- |
|       |                                                           |
| 5     | Proportional Uniform Distribution: Each counter for an    |
|       | Original Flow is divided by the number of time units the  |
|       | Original Flow covers, to derive a mean count rate.  This  |
|       | mean count rate is then multiplied by the number of time  |
|       | units in the intersection of the duration of the Original |
|       | Flow and the time interval of each Aggregated Flow.  This |
|       | is like simple uniform distribution, but accounts for the |
|       | fractional portions of a time interval covered by an      |
|       | Original Flow in the first and last time interval.        |
|       | --------------------------------------------------------- |
|       |                                                           |
| 6     | Simulated Process: Each counter of the Original Flow is   |
|       | distributed among the intervals of the Aggregated Flows   |
|       | according to some function the Intermediate Aggregation   |
|       | Process uses based upon properties of Flows presumed to   |
|       | be like the Original Flow.  This is essentially an        |
|       | assertion that the Intermediate Aggregation Process has   |
|       | no direct packet timing information but is nevertheless   |
|       | not using one of the other simpler distribution methods.  |
|       | The Intermediate Aggregation Process specifically makes   |
|       | no assertion as to the correctness of the simulation.     |
|       | --------------------------------------------------------- |
|       |                                                           |
| 7     | Direct: The Intermediate Aggregation Process has access   |
|       | to the original packet timings from the packets making up |
|       | the Original Flow, and uses these to distribute or        |
|       | recalculate the counters.                                 |
+-------+-----------------------------------------------------------+
```"),
385 => (Rfc3550JitterMilliseconds, rfc3550_jitter_milliseconds, u32, (), doc="Interarrival jitter as defined in section 6.4.1 of [RFC3550],
measured in milliseconds."),
386 => (Rfc3550JitterMicroseconds, rfc3550_jitter_microseconds, u32, (), doc="Interarrival jitter as defined in section 6.4.1 of [RFC3550],
measured in microseconds."),
387 => (Rfc3550JitterNanoseconds, rfc3550_jitter_nanoseconds, u32, (), doc="Interarrival jitter as defined in section 6.4.1 of [RFC3550],
measured in nanoseconds."),
388 => (Dot1qDEI, dot1q_dei, bool, (), doc="The value of the 1-bit Drop Eligible Indicator (DEI) field of the VLAN tag as
described in 802.1Q-2011 subclause 9.6. In case of a QinQ frame, it represents
the outer tag's DEI field and in case of an IEEE 802.1ad frame it represents
the DEI field of the S-TAG. Note: in earlier versions of 802.1Q the same bit
field in the incoming packet is occupied by the Canonical Format Indicator
(CFI) field, except for S-TAGs."),
389 => (Dot1qCustomerDEI, dot1q_customer_dei, bool, (), doc="In case of a QinQ frame, it represents the inner tag's Drop Eligible Indicator
 (DEI) field and in case of an IEEE 802.1ad frame it represents the DEI field of
 the C-TAG."),
390 => (FlowSelectorAlgorithm, flow_selector_algorithm, u16, (), doc="This Information Element identifies the Intermediate Flow
Selection Process technique (e.g., Filtering, Sampling) that is
applied by the Intermediate Flow Selection Process.  Most of these
techniques have parameters.  Its configuration parameter(s) MUST
be clearly specified.  Further Information Elements are needed to
fully specify packet selection with these methods and all their
parameters.  Further method identifiers may be added to the
flowSelectorAlgorithm registry.  It might be necessary to define new Information Elements
to specify their parameters.  The flowSelectorAlgorithm registry
is maintained by IANA.  New assignments for the registry will be
administered by IANA, on a First Come First Served basis
[RFC5226], subject to Expert Review [RFC5226].  Please note that
the purpose of the flow selection techniques described in this
document is the improvement of measurement functions as defined in
the Scope (Section 1).  Before adding new flow selector algorithms
it should be checked what is their intended purpose and especially
if those contradict with policies defined in [RFC2804].  The
designated expert(s) should consult with the community if a
request is received that runs counter to [RFC2804].  The registry
can be updated when specifications of the new method(s) and any
new Information Elements are provided.  The group of experts must
double check the flowSelectorAlgorithm definitions and Information
Elements with already defined flowSelectorAlgorithm and
Information Elements for completeness, accuracy, and redundancy.
Those experts will initially be drawn from the Working Group
Chairs and document editors of the IPFIX and PSAMP Working Groups.
The Intermediate Flow Selection Process Techniques
identifiers are defined at [http://www.iana.org/assignments/ipfix/ipfix.xml#ipfix-flowselectoralgorithm]."),
391 => (FlowSelectedOctetDeltaCount, flow_selected_octet_delta_count, u64, (), doc="This Information Element specifies the volume in octets of all
Flows that are selected in the Intermediate Flow Selection Process
since the previous report."),
392 => (FlowSelectedPacketDeltaCount, flow_selected_packet_delta_count, u64, (), doc="This Information Element specifies the volume in packets of all
Flows that were selected in the Intermediate Flow Selection
Process since the previous report."),
393 => (FlowSelectedFlowDeltaCount, flow_selected_flow_delta_count, u64, (), doc="This Information Element specifies the number of Flows that were
 selected in the Intermediate Flow Selection Process since the last
 report."),
394 => (SelectorIDTotalFlowsObserved, selector_id_total_flows_observed, u64, (), doc="This Information Element specifies the total number of Flows
observed by a Selector, for a specific value of SelectorId.  This
Information Element should be used in an Options Template scoped
to the observation to which it refers.  See Section 3.4.2.1 of the
IPFIX protocol document [RFC7011]."),
395 => (SelectorIDTotalFlowsSelected, selector_id_total_flows_selected, u64, (), doc="This Information Element specifies the total number of Flows
selected by a Selector, for a specific value of SelectorId.  This
Information Element should be used in an Options Template scoped
to the observation to which it refers.  See Section 3.4.2.1 of the
IPFIX protocol document [RFC7011]."),
396 => (SamplingFlowInterval, sampling_flow_interval, u64, (), doc="This Information Element specifies the number of Flows that are
consecutively sampled.  A value of 100 means that 100 consecutive
Flows are sampled.  For example, this Information Element may be
used to describe the configuration of a systematic count-based
Sampling Selector."),
397 => (SamplingFlowSpacing, sampling_flow_spacing, u64, (), doc="This Information Element specifies the number of Flows between two
\"samplingFlowInterval\"s.  A value of 100 means that the next
interval starts 100 Flows (which are not sampled) after the
current \"samplingFlowInterval\" is over.  For example, this
Information Element may be used to describe the configuration of a
systematic count-based Sampling Selector."),
398 => (FlowSamplingTimeInterval, flow_sampling_time_interval, u64, (), doc="This Information Element specifies the time interval in
microseconds during which all arriving Flows are sampled.  For
example, this Information Element may be used to describe the
configuration of a systematic time-based Sampling Selector."),
399 => (FlowSamplingTimeSpacing, flow_sampling_time_spacing, u64, (), doc="This Information Element specifies the time interval in
microseconds between two \"flowSamplingTimeInterval\"s.  A value of
100 means that the next interval starts 100 microseconds (during
which no Flows are sampled) after the current
\"flowsamplingTimeInterval\" is over.  For example, this Information
Element may used to describe the configuration of a systematic
time-based Sampling Selector."),
400 => (HashFlowDomain, hash_flow_domain, u16, (), doc="This Information Element specifies the Information Elements that
are used by the Hash-based Flow Selector as the Hash Domain."),
401 => (TransportOctetDeltaCount, transport_octet_delta_count, u64, (), doc="The number of octets, excluding IP header(s) and Layer 4 transport
protocol header(s), observed for this Flow at the Observation Point
since the previous report (if any)."),
402 => (TransportPacketDeltaCount, transport_packet_delta_count, u64, (), doc="The number of packets containing at least one octet beyond the IP header(s) and
Layer 4 transport protocol header(s), observed for this Flow at the Observation
Point since the previous report (if any)."),
403 => (OriginalExporterIpv4Address, original_exporter_ipv4_address, [u8; 4], (), doc="The IPv4 address used by the Exporting Process on an
Original Exporter, as seen by the Collecting Process on an IPFIX
Mediator.  Used to provide information about the Original
Observation Points to a downstream Collector."),
404 => (OriginalExporterIpv6Address, original_exporter_ipv6_address, [u8; 16], (), doc="The IPv6 address used by the Exporting Process on an
Original Exporter, as seen by the Collecting Process on an IPFIX
Mediator.  Used to provide information about the Original
Observation Points to a downstream Collector."),
405 => (OriginalObservationDomainId, original_observation_domain_id, u32, (), doc="The Observation Domain ID reported by the Exporting
Process on an Original Exporter, as seen by the Collecting Process
on an IPFIX Mediator.  Used to provide information about the
Original Observation Domain to a downstream Collector.  When
cascading through multiple Mediators, this identifies the initial
Observation Domain in the cascade."),
406 => (IntermediateProcessId, intermediate_process_id, u32, (), doc="Description: An identifier of an Intermediate Process that is
unique per IPFIX Device. Typically, this Information Element is
used for limiting the scope of other Information Elements. Note
that process identifiers may be assigned dynamically; that is, an
Intermediate Process may be restarted with a different ID."),
407 => (IgnoredDataRecordTotalCount, ignored_data_record_total_count, u64, (), doc="Description: The total number of received Data Records that the
Intermediate Process did not process since the (re-)initialization
of the Intermediate Process; includes only Data Records not
examined or otherwise handled by the Intermediate Process due to
resource constraints, not Data Records that were examined or
otherwise handled by the Intermediate Process but those that
merely do not contribute to any exported Data Record due to the
operations performed by the Intermediate Process."),
408 => (DataLinkFrameType, data_link_frame_type, u16, (), doc="This Information Element specifies the type of the selected data
link frame.




The following data link types are defined here:




- 0x01 IEEE802.3 ETHERNET [IEEE802.3]




- 0x02 IEEE802.11 MAC Frame format [IEEE802.11]




Further values may be assigned by IANA.  Note that the assigned
values are bits so that multiple observations can be OR'd
together.




The data link layer is defined in [ISO/IEC.7498-1:1994]."),
409 => (SectionOffset, section_offset, u16, (), doc="This Information Element specifies the offset of the packet
section (e.g., dataLinkFrameSection, ipHeaderPacketSection,
ipPayloadPacketSection, mplsLabelStackSection, and
mplsPayloadPacketSection).  If this Information Element is
omitted, it defaults to zero (i.e., no offset).




If multiple sectionOffset Information Elements are specified
within a single Template, then they apply to the packet section
Information Elements in order: the first sectionOffset applies to
the first packet section, the second to the second, and so on.
Note that the \"closest\" sectionOffset and packet section
Information Elements within a given Template are not necessarily
related.  If there are fewer sectionOffset Information Elements
than packet section Information Elements, then subsequent packet
section Information Elements have no offset, i.e., a sectionOffset
of zero applies to those packet section Information Elements.  If
there are more sectionOffset Information Elements than the number
of packet section Information Elements, then the additional
sectionOffset Information Elements are meaningless."),
410 => (SectionExportedOctets, section_exported_octets, u16, (), doc="This Information Element specifies the observed length of the
packet section (e.g., dataLinkFrameSection, ipHeaderPacketSection,
ipPayloadPacketSection, mplsLabelStackSection, and
mplsPayloadPacketSection) when padding is used.




The packet section may be of a fixed size larger than the
sectionExportedOctets.  In this case, octets in the packet section
beyond the sectionExportedOctets MUST follow the [RFC7011] rules
for padding (i.e., be composed of zero (0) valued octets)."),
411 => (Dot1qServiceInstanceTag, dot1q_service_instance_tag, octetArray, (), doc="This Information Element, which is 16 octets long, represents the
Backbone Service Instance Tag (I-TAG) Tag Control Information
(TCI) field of an Ethernet frame as described in [IEEE802.1Q].  It
encodes the Backbone Service Instance Priority Code Point (I-PCP),
Backbone Service Instance Drop Eligible Indicator (I-DEI), Use Customer Addresses (UCAs),
Backbone Service Instance Identifier (I-SID), Encapsulated
Customer Destination Address (C-DA), Encapsulated Customer Source
Address (C-SA), and reserved fields.  The structure and semantics
within the Tag Control Information field are defined in
[IEEE802.1Q]."),
412 => (Dot1qServiceInstanceId, dot1q_service_instance_id, u32, (), doc="The value of the 24-bit Backbone Service Instance Identifier
(I-SID) portion of the Backbone Service Instance Tag (I-TAG) Tag
Control Information (TCI) field of an Ethernet frame as described
in [IEEE802.1Q]."),
413 => (Dot1qServiceInstancePriority, dot1q_service_instance_priority, u8, (), doc="The value of the 3-bit Backbone Service Instance Priority Code
Point (I-PCP) portion of the Backbone Service Instance Tag (I-TAG)
Tag Control Information (TCI) field of an Ethernet frame as
described in [IEEE802.1Q]."),
414 => (Dot1qCustomerSourceMacAddress, dot1q_customer_source_mac_address, [u8;6], (), doc="The value of the Encapsulated Customer Source Address (C-SA)
portion of the Backbone Service Instance Tag (I-TAG) Tag Control
Information (TCI) field of an Ethernet frame as described in
[IEEE802.1Q]."),
415 => (Dot1qCustomerDestinationMacAddress, dot1q_customer_destination_mac_address, [u8;6], (), doc="The value of the Encapsulated Customer Destination Address (C-DA)
portion of the Backbone Service Instance Tag (I-TAG) Tag Control
Information (TCI) field of an Ethernet frame as described in
[IEEE802.1Q]."),
417 => (PostLayer2OctetDeltaCount, post_layer2_octet_delta_count, u64, (), doc="The definition of this Information Element is identical to the
definition of the layer2OctetDeltaCount Information Element,
except that it reports a potentially modified value caused by a
middlebox function after the packet passed the Observation Point.




This Information Element is the layer 2 version of
postOctetDeltaCount (ElementId #23)."),
418 => (PostMcastLayer2OctetDeltaCount, post_mcast_layer2_octet_delta_count, u64, (), doc="The number of layer 2 octets since the previous report (if any) in
outgoing multicast packets sent for packets of this Flow by a
multicast daemon within the Observation Domain.  This property
cannot necessarily be observed at the Observation Point but may
be retrieved by other means.  The number of octets includes layer
2 header(s) and layer 2 payload.




This Information Element is the layer 2 version of
postMCastOctetDeltaCount (ElementId #20)."),
420 => (PostLayer2OctetTotalCount, post_layer2_octet_total_count, u64, (), doc="The definition of this Information Element is identical to the
definition of the layer2OctetTotalCount Information Element,
except that it reports a potentially modified value caused by a
middlebox function after the packet passed the Observation Point.




This Information Element is the layer 2 version of
postOctetTotalCount (ElementId #171)."),
421 => (PostMcastLayer2OctetTotalCount, post_mcast_layer2_octet_total_count, u64, (), doc="The total number of layer 2 octets in outgoing multicast packets
sent for packets of this Flow by a multicast daemon in the
Observation Domain since the Metering Process (re-)initialization.
This property cannot necessarily be observed at the Observation
Point but may be retrieved by other means.  The number of octets
includes layer 2 header(s) and layer 2 payload.




This Information Element is the layer 2 version of
postMCastOctetTotalCount (ElementId #175)."),
422 => (MinimumLayer2TotalLength, minimum_layer2_total_length, u64, (), doc="Layer 2 length of the smallest packet observed for this Flow.  The
packet length includes the length of the layer 2 header(s) and the
length of the layer 2 payload.




This Information Element is the layer 2 version of
minimumIpTotalLength (ElementId #25)."),
423 => (MaximumLayer2TotalLength, maximum_layer2_total_length, u64, (), doc="Layer 2 length of the largest packet observed for this Flow.  The
packet length includes the length of the layer 2 header(s) and the length of the layer
2 payload.




This Information Element is the layer 2 version of
maximumIpTotalLength (ElementId #26)."),
424 => (DroppedLayer2OctetDeltaCount, dropped_layer2_octet_delta_count, u64, (), doc="The number of layer 2 octets since the previous report (if any) in
packets of this Flow dropped by packet treatment.  The number of
octets includes layer 2 header(s) and layer 2 payload.




This Information Element is the layer 2 version of
droppedOctetDeltaCount (ElementId #132)."),
425 => (DroppedLayer2OctetTotalCount, dropped_layer2_octet_total_count, u64, (), doc="The total number of octets in observed layer 2 packets (including
the layer 2 header) that were dropped by packet treatment since
the (re-)initialization of the Metering Process.




This Information Element is the layer 2 version of
droppedOctetTotalCount (ElementId #134)."),
426 => (IgnoredLayer2OctetTotalCount, ignored_layer2_octet_total_count, u64, (), doc="The total number of octets in observed layer 2 packets (including
the layer 2 header) that the Metering Process did not process
since the (re-)initialization of the Metering Process.




This Information Element is the layer 2 version of
ignoredOctetTotalCount (ElementId #165)."),
427 => (NotSentLayer2OctetTotalCount, not_sent_layer2_octet_total_count, u64, (), doc="The total number of octets in observed layer 2 packets (including
the layer 2 header) that the Metering Process did not process
since the (re-)initialization of the Metering Process.




This Information Element is the layer 2 version of
notSentOctetTotalCount (ElementId #168)."),
428 => (Layer2OctetDeltaSumOfSquares, layer2_octet_delta_sum_of_squares, u64, (), doc="The sum of the squared numbers of layer 2 octets per incoming
packet since the previous report (if any) for this Flow at the
Observation Point.  The number of octets includes layer 2
header(s) and layer 2 payload.




This Information Element is the layer 2 version of
octetDeltaSumOfSquares (ElementId #198)."),
429 => (Layer2OctetTotalSumOfSquares, layer2_octet_total_sum_of_squares, u64, (), doc="The total sum of the squared numbers of layer 2 octets in incoming
packets for this Flow at the Observation Point since the Metering
Process (re-)initialization for this Observation Point.  The
number of octets includes layer 2 header(s) and layer 2 payload.




This Information Element is the layer 2 version of
octetTotalSumOfSquares (ElementId #199)."),
430 => (Layer2FrameDeltaCount, layer2_frame_delta_count, u64, (), doc="The number of incoming layer 2 frames since the
previous report (if any) for this Flow at the
Observation Point."),
431 => (Layer2FrameTotalCount, layer2_frame_total_count, u64, (), doc="The total number of incoming layer 2 frames
for this Flow at the Observation Point since
the Metering Process (re-)initialization for
this Observation Point."),
432 => (PseudoWireDestinationIpv4Address, pseudo_wire_destination_ipv4_address, [u8; 4], (), doc="The destination IPv4 address of the PSN tunnel carrying the pseudowire."),
433 => (IgnoredLayer2FrameTotalCount, ignored_layer2_frame_total_count, u64, (), doc="The total number of observed layer 2 frames that the Metering Process
did not process since the (re-)initialization of the Metering Process.
This Information Element is the layer 2 version of ignoredPacketTotalCount (ElementId #164)."),
}

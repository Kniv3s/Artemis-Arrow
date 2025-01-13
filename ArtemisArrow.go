package main 
import (
	"fmt" 
	"net"
	"log"  
	"os" 
	"io"
	"errors"
	"encoding/json"
	"encoding/binary"
	"github.com/google/gopacket" 
	"github.com/google/gopacket/pcap"
	_ "github.com/google/gopacket/layers" //best practice to import for variable init
) 
//configuration file structure
type Config struct {
	DestHost string `json:"destHost"`
	ControlNet string `json:"controlNet"`
	DestPort int    `json:"destPort"`
	VNI      uint32 `json:"vni"`
	Filter	 string `json:"filter"`
}
//helper for the VXLAN header
type VXLANHeader struct {
	Flags     uint8
	Reserved1 uint16
	VNI       uint32
	Reserved2 uint8
}
//constants
const (
	VXLAN_HEADER_SIZE     = 8 //header size from RFC
	PORT_MIN             = 49152 //port min and max from RFC
	PORT_MAX             = 65535 //port min and max from RFC
	PORT_RANGE           = PORT_MAX - PORT_MIN + 1
	VERBOSE				 = 2 //2 is everything, 1 everything but packet send, 0 is none
	SEND_PACKET			 = true //for debuggin without packets
)
//global variables for config to load into
var destHost string
var controlNet string
var destPort int
var vni uint32
var filter string
//helper function for error logging
//err		the possible error being logged (nil is fine)
//msg		what to log should an error be passed
//fatal		optional bool if false will not be fatal, just logged
//
//returns	true if a non-fatal error was logged, false otherwise
func logError(err error, msg string, fatal_ ...bool) bool {
	fatal := true
	if len(fatal_) > 0 {
		fatal = fatal_[0]
	}
	if err != nil {
		if fatal {
			log.Fatalf("%s: %v", msg, err)
			return false
		} 
		if VERBOSE > 0 {
			log.Printf(msg)
			return true
		}
	}
	return false
}
//loads the config json and populates global vars
//filename		the filename of the config file
//
//error	Any error that is encounted gets returned
func loadConfig(filename string) error {
    file, err := os.ReadFile(filename)
    if err != nil {
        return err
    }
    var config Config
    if err := json.Unmarshal(file, &config); err != nil {
        return err
    }
    destHost = config.DestHost
	controlNet = config.ControlNet
	vni = config.VNI
	destPort = config.DestPort
	filter = config.Filter
	if destHost == "" || destPort < 0 {
		return errors.New(fmt.Sprintf("%s:%s is not a valid ip:port combo", destHost, destPort))
	}
	return nil
}
//capture traffic from a given device name and handle all packets not filtered
//deviceName		the pcap diven device name that will be listened on
func captureFromInterface(deviceName string) { 
	handle, err := pcap.OpenLive(deviceName, 65536, true, pcap.BlockForever) 
	//allow for the pcap to not open and just skip interface
	if logError(err, fmt.Sprintf("Failed to open %s for packet capture", deviceName), false) {
		return
	}
	defer handle.Close() 
	//build the filter based off of what is given in the config
	var filter_ string
	if filter != "" {
		filter_ = fmt.Sprintf("( %s ) and not (udp and dst host %s and dst port %d)",filter, destHost, destPort)
	} else {
		filter_ = fmt.Sprintf("not (udp and dst host %s and dst port %d)", destHost, destPort)
	}
	//apply filter and capture
	if VERBOSE > 0 {
		log.Printf("%s Capturing with Filter: %s", deviceName,  filter_) 
	}
	//allow for the filter to fail at application and just skip interface
	if logError(handle.SetBPFFilter(filter_), fmt.Sprintf("Failed to set filter '%s' on %s", filter_, deviceName), false) {
		return
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType()) 
	for packet := range packetSource.Packets() { 
		//handle any packets that arcaptured
		srcPort := calculateSourcePort(packet)
		packet := encapsulateVXLAN(packet.Data())
		if SEND_PACKET {
			sendUDPPacket(srcPort, packet)
		}
	} 
}
//helper function to calculate source port based on the originial pre-encapsulation packet for sending
//off to a VXLAN endpoint. RFC recomends source port be based off a hash of orinial packet ipv4 info,
//but we are fibbing a bit as this is a non-standard use of VXLAN.
//packet		the original packet pre-encapsulation
//
//srcPort		a possitive number between 49152 and 65535 based on a hash of the netflow 
func calculateSourcePort(packet gopacket.Packet) (srcPort uint16) {
	//should a netflow not be able to be created form packet, default to 65535
	defer func() {
		if r := recover(); r != nil {
			srcPort = PORT_MAX
		}
	}()
	//netflow hash has usful functionality, mostly in directionality parity
	//i.e. A:a->B:b will hash the same as B:b->A:a
	netFlow := packet.NetworkLayer().NetworkFlow()
	return uint16( (netFlow.FastHash() % PORT_RANGE) + PORT_MIN )
}
//helper function to prepend a VXLAN header to the packet with the config derived info
//packet		the byte array of the packet. should be all bytes from original packet
//
//returns		the encapsulated packet data. this hsould be the payload of a UDP packet sent to a VXLAN endpoint
func encapsulateVXLAN(packet []byte) []byte {
    header := VXLANHeader{
        Flags: 0x08,
        VNI:   vni,
    }
    vxlanPacket := make([]byte, VXLAN_HEADER_SIZE+len(packet))
    binary.BigEndian.PutUint32(vxlanPacket[0:4], uint32(header.Flags)<<24|uint32(header.Reserved1))
    binary.BigEndian.PutUint32(vxlanPacket[4:8], header.VNI<<8|uint32(header.Reserved2))
    copy(vxlanPacket[8:], packet)
    return vxlanPacket
}
//helper function to create the connection and send the packet
//srcPort		the source port to send from
//payload		the payload of the packet to send. should be a VXLAN encapsulated packet without a L2 or L3 header		
func sendUDPPacket(srcPort uint16, payload []byte) {
	//bind local and remote port, then open
	// if any errors are encounted log and discard packet
    localAddr := &net.UDPAddr{Port: int(srcPort)}
    remoteAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", destHost, destPort))
    if logError(err, fmt.Sprintf("Failed to resolve %s:%d", destHost, destPort), false) {
		return
	}
    vxlanConn, err := net.DialUDP("udp", localAddr, remoteAddr)
	if logError(err, fmt.Sprintf("Error creating VXLAN connection for port %d", srcPort), false ) {
		return
	}
	defer vxlanConn.Close()
	//send packet, log error and continue if failed
	_, err = vxlanConn.Write(payload)
	if logError(err, "Error sending VXLAN payload: ", false) {
		return
	}
	//log successful packet send
	if VERBOSE == 2 {
		log.Printf("sent payload %b", payload)
	}
}
//main function
func main() { 
	//send output to trash if live
	if VERBOSE == 0 {
		log.SetOutput(io.Discard)
	}
	//load config and populate global vars
	logError(loadConfig("config.json"), "Failed to load config")
	//grab devices
	devices, err := pcap.FindAllDevs() 
	logError(err, "Failed to grab devices") 
	if len(devices) == 0 { 
		fmt.Println("No devices found.") 
		os.Exit(1) 
	} 
	//sort what devices to listen on
	for _, device := range devices { 
		listen := true
		_, control, err := net.ParseCIDR(controlNet)
		logError(err, "Failed to parse control network CIDR")
		for _, add := range device.Addresses {
			ip := add.IP
			if VERBOSE > 0 {
				log.Printf("%s with ip %s", device.Name, add.IP)
			}
			//dont listen on loopback or control interfaces
			if ip.IsLoopback() || control.Contains(ip) || ip == nil {
				if VERBOSE > 0 {
					log.Printf("discarded")
				}
				listen = false
			}
		}
		if listen {
			if VERBOSE > 0 {
				log.Printf("Captureing traffic on %s description: %s", device.Name, device.Description)
			}
			go captureFromInterface(device.Name) 
		}
	} 
	select {} 
}

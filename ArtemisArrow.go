package main 
import (
    "fmt" 
	"net"
    "log"  
    "os" 
	"io"
	"time"
    "encoding/json"
	"encoding/binary"
    "github.com/google/gopacket" 
    "github.com/google/gopacket/pcap"
	_ "github.com/google/gopacket/layers"
) 
type Config struct {
    DestHost string `json:"destHost"`
    DestPort int    `json:"destPort"`
    VNI      uint32 `json:"vni"`
}
type VXLANHeader struct {
    Flags     uint8
    Reserved1 uint16
    VNI       uint32
    Reserved2 uint8
}
const (
    VXLAN_HEADER_SIZE     = 8
    UDP_HEADER_SIZE       = 8
    IP_HEADER_SIZE        = 20
    IP_HEADER_MIN         = 20
    ETHERNET_HEADER_SIZE  = 14
    MIN_FRAGMENT_SIZE     = 576
    INTERFACE_TEST_TIMEOUT = 2 * time.Second
    PORT_MIN             = 49152
    PORT_MAX             = 65535
    PORT_RANGE           = PORT_MAX - PORT_MIN + 1
)

var destHost string
var destPort int
var vni uint32


func main() { 
	log.SetOutput(io.Discard) //comment out this line for logging to consol
	
	err := loadConfig("config.json")
    if err != nil {
        log.Fatalf("Error loading config: %v", err)
    }

	devices, err := pcap.FindAllDevs() 
	if err != nil { 
		log.Fatal(err) 
	} 
	// Check if there are any devices found
	if len(devices) == 0 { 
		fmt.Println("No devices found.") 
		os.Exit(1) 
	} 
	// Loop through all devices 
	for _, device := range devices { 
		listen := true
		_, control, err := net.ParseCIDR("10.10.0.0/16")
		if err != nil { 
			log.Fatal(err) 
		}	
		for _, add := range device.Addresses {
			ip := add.IP
			log.Printf("%s with ip %s", device.Name, add.IP)
			if ip.IsLoopback() || control.Contains(ip) || ip == nil {
				log.Printf("discarded")
				listen = false
			}
		}
		if listen {
			log.Printf("Captureing traffic on %s description: %s", device.Name, device.Description)
			go captureFromInterface(device.Name, destHost, destPort, vni) 
		}
	} 
	// Prevent the main function from exiting 
	select {} 
} 
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
	vni = config.VNI
	destPort = config.DestPort
	return nil
}
func captureFromInterface(deviceName string, dhost string, dport int, vni uint32) { 
	// Open the device 
	handle, err := pcap.OpenLive(deviceName, 65536, true, pcap.BlockForever) 
	if err != nil { 
		log.Fatal(err) 
	} 
	defer handle.Close() 
	// Set filter 
	var	filter string = fmt.Sprintf("not (udp and dst host %s and dst port %d)", dhost, dport)
	log.Printf("%s Capturing with Filter: %s", deviceName,  filter) 
	// Example: capture only TCP traffic on port 80 
	err = handle.SetBPFFilter(filter) 
	if err != nil { 
		log.Fatal(err) 
	} 
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType()) 
	for packet := range packetSource.Packets() { 
		handlePacket(packet)
	} 
}
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
func handlePacket (packet_ gopacket.Packet) {
	srcPort := calculateSourcePort(packet_)
	packet := encapsulateVXLAN(packet_.Data())
	sendUDPPacket(srcPort, packet)
}

func calculateSourcePort(packet gopacket.Packet) (srcPort uint16) {
	defer func() {
		if r := recover(); r != nil {
			srcPort = 5055
		}
	}()
	netFlow := packet.NetworkLayer().NetworkFlow()
	return uint16( (netFlow.FastHash() % PORT_RANGE) + PORT_MIN )
}

func sendUDPPacket(srcPort uint16, fragment []byte) error {
    localAddr := &net.UDPAddr{Port: int(srcPort)}
    remoteAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", destHost, destPort))
    if err != nil {
        return err
    }
    vxlanConn, err := net.DialUDP("udp", localAddr, remoteAddr)
	if err != nil {
		log.Printf("Error creating VXLAN connection for port %d: %v", srcPort, err)
		return err
	}
	defer vxlanConn.Close()
	_, err = vxlanConn.Write(fragment)
	if err != nil {
		log.Printf("Error sending VXLAN fragment: %v", err)
		return err
	}
	log.Printf("sent packet %b", fragment)
	return nil
}
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

func main() {

	var domain string
	var interfaceName string
	var outputFile string
	var packetCount int
	flag.StringVar(&domain, "d", "", "指定dns解析的域名")
	flag.StringVar(&interfaceName, "i", "eth0", "指定捕获数据包的网口")
	flag.StringVar(&outputFile, "o", "", "指定输出的文件名")
	flag.IntVar(&packetCount, "w", -1, "指定抓取数据包数量")
	flag.Parse()

	if domain == "" {
		log.Fatal("域名(-d)是必需参数")
	}

	if outputFile == "" {
		outputFile = fmt.Sprintf("result-%s.pcap", time.Now().Format("20060102150405"))
	}

	handle, err := pcap.OpenLive(interfaceName, 1024, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("udp and port 53"); err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	fHandle, err := os.Create(outputFile)
	if err != nil {
		log.Fatal(err)
	}
	defer fHandle.Close()

	w := pcapgo.NewWriter(fHandle)
	if err := w.WriteFileHeader(1024, layers.LinkTypeEthernet); err != nil {
		log.Fatal(err)
	}

	captured := 0
	for packet := range packetSource.Packets() {
		if isDNSQueryForDomain(packet, domain) {
			if err := w.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
				log.Println("将数据包写入文件时出错:", err)
			}
			captured++
			if packetCount > 0 && captured >= packetCount {
				break
			}
		}
	}
}

func isDNSQueryForDomain(packet gopacket.Packet, domain string) bool {
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer != nil {
		dns, _ := dnsLayer.(*layers.DNS)
		for _, query := range dns.Questions {
			if strings.Contains(string(query.Name), domain) {
				return true
			}
		}
	}
	return false
}

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"sync"
	"time"

	_ "net/http/pprof"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/afpacket"
	"github.com/gopacket/gopacket/layers"
)

var accounts Accounts

type Accounts struct {
	Mapping []Mapping `json:"accounts"`
}

type Mapping struct {
	IPrange       netip.Prefix                 `json:"ipRange"`
	ARNrole       string                       `json:"arnRole"`
	lastEc2DataAt time.Time                    `json:"-"`
	lastEc2Data   *ec2.DescribeInstancesOutput `json:"-"`
	lastEc2Err    error                        `json:"-"`
	ec2Svc        *ec2.Client                  `json:"-"`
}

func LoadMapping(filePath string) error {
	// Load mapping JSON config file and parse it
	jsonFile, err := os.Open(filePath)
	if err != nil {
		log.Printf("error opening mapping.json file, %v", err)
		return err
	} else {
		defer jsonFile.Close()

		byteValue, _ := io.ReadAll(jsonFile)
		json.Unmarshal(byteValue, &accounts)

		return nil
	}

}

func GetMappingFromIP(ip netip.Addr) (*Mapping, error) {
	// return corresponding mapping for specified IP
	for _, mapping := range accounts.Mapping {

		if mapping.IPrange.Contains(ip) {
			return &mapping, nil
		}
	}
	return nil, errors.New("ip block not found in mapping.json file")
}

func GetEC2Data(mapping *Mapping, cfg aws.Config) (*ec2.DescribeInstancesOutput, error) {
	// Cache EC2 instance data for 5s
	if mapping.lastEc2DataAt.Add(5 * time.Second).After(time.Now()) {
		return mapping.lastEc2Data, mapping.lastEc2Err
	}

	if mapping.ARNrole == "Ec2InstanceMetadata" {
		//We use IAM role attached to the instance
		mapping.ec2Svc = ec2.NewFromConfig(cfg)

	} else {
		// We assume ARN role
		stsSvc := sts.NewFromConfig(cfg)
		creds := stscreds.NewAssumeRoleProvider(stsSvc, mapping.ARNrole)
		cfg.Credentials = aws.NewCredentialsCache(creds)

		mapping.ec2Svc = ec2.NewFromConfig(cfg)
	}

	input := &ec2.DescribeInstancesInput{
		Filters: []types.Filter{
			{
				Name: aws.String("tag:autostart"),
				Values: []string{
					"true",
				},
			},
		},
	}
	mapping.lastEc2Data, mapping.lastEc2Err = mapping.ec2Svc.DescribeInstances(context.TODO(), input)
	mapping.lastEc2DataAt = time.Now()
	return mapping.lastEc2Data, mapping.lastEc2Err
}

var suppressions = make(map[string]struct{})
var suppressionLock sync.Mutex

func suppressRefused(ip string) {
	suppressionLock.Lock()
	defer suppressionLock.Unlock()
	if _, ok := suppressions[ip]; ok {
		return
	}
	log.Println("Temporarily suppressing RST from", ip)
	cmd := exec.Command("/usr/sbin/iptables", "-I", "FORWARD", "-p", "tcp", "-s", ip, "--tcp-flags", "ALL", "RST,ACK", "-j", "DROP")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Printf("Failed to suppress RST from %s: %s", ip, err)
	} else {
		suppressions[ip] = struct{}{}
	}
	time.AfterFunc(30*time.Second, func() {
		suppressionLock.Lock()
		defer suppressionLock.Unlock()
		log.Println("Unsuppressing RST from", ip)
		cmd := exec.Command("/usr/sbin/iptables", "-D", "FORWARD", "-p", "tcp", "-s", ip, "--tcp-flags", "ALL", "RST,ACK", "-j", "DROP")
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			log.Printf("Failed to unsuppress RST from %s: %s", ip, err)
		} else {
			delete(suppressions, ip)
		}
	})
}

func main() {
	if os.Getenv("PPROF_ADDR") != "" {
		go func() {
			log.Println("Listening for profiling on", os.Getenv("PPROF_ADDR"))
			log.Println(http.ListenAndServe(os.Getenv("PPROF_ADDR"), nil))
		}()
	}
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	//Load Account Network Mapping
	err = LoadMapping(os.Args[2])
	if err != nil {
		log.Fatalf("unable to load mapping config, %v", err)
	}

	tpacket, err := afpacket.NewTPacket()
	// handle, err := pcap.OpenLive(os.Args[1], 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var tcp layers.TCP
	decoded := []gopacket.LayerType{}

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &tcp)

	for {
		data, _, err := tpacket.ZeroCopyReadPacketData()
		if err != nil {
			log.Fatal("Error reading packet", err)
		}

		tcp.SYN = false // Ensure the decoder below MUST set the TCP layer to continue

		parser.DecodeLayers(data, &decoded)

		if !(tcp.SYN && !tcp.ACK) {
			continue // Only process SYN Packets
		}

		dst, ok := netip.AddrFromSlice(ip4.DstIP)
		if !ok {
			log.Println("Failed to parse IP", ip4.DstIP)
			continue
		}

		mapping, err := GetMappingFromIP(dst)
		if err != nil {
			// This happens for traffic to any public IP. Disregard.
			continue
		}

		instances, err := GetEC2Data(mapping, cfg)
		if err != nil {
			log.Println("Failed to get EC2 status", err)
		}

		for _, res := range instances.Reservations {
			for _, instance := range res.Instances {
				if instance.PrivateIpAddress == nil {
					continue
				}
				if *instance.PrivateIpAddress != dst.String() {
					continue
				}
				if instance.State == nil {
					continue
				}
				if instance.State.Name != "stopped" {
					continue
				}
				log.Println("Starting", dst.String(), instance.InstanceId)
				_, err := mapping.ec2Svc.StartInstances(context.TODO(), &ec2.StartInstancesInput{InstanceIds: []string{*instance.InstanceId}})
				if err != nil {
					log.Println("Failed to start instance", err)
				} else {
					suppressRefused(dst.String())
				}

				// Force refresh of EC2 instance data
				mapping.lastEc2DataAt = time.Time{}

			}
		}
	}
}

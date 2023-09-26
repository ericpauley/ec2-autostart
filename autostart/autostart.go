package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var accounts Accounts

type Accounts struct {
	Mapping []Mapping `json:"accounts"`
}

type Mapping struct {
	IPrange       string                       `json:"ipRange"`
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

func GetMappingFromIP(ip string) (*Mapping, error) {
	// return corresponding mapping for specified IP
	for i := 0; i < len(accounts.Mapping); i++ {
		_, subnet, err := net.ParseCIDR(accounts.Mapping[i].IPrange)
		if err != nil {
			return nil, errors.New("error parsing network")
		}

		if subnet.Contains(net.ParseIP(ip)) {
			return &accounts.Mapping[i], nil
		}
	}
	return nil, errors.New("ip block not found in mapping.json file")
}

func GetEC2Data(mapping *Mapping) (*ec2.DescribeInstancesOutput, error) {
	// Cache EC2 instance data for 5s
	if mapping.lastEc2DataAt.Add(5 * time.Second).After(time.Now()) {
		return mapping.lastEc2Data, mapping.lastEc2Err
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

var suppressions map[string]struct{}
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
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	//Load Account Network Mapping
	err = LoadMapping(os.Args[2])
	if err != nil {
		log.Fatalf("unable to load mapping config, %v", err)
	}

	handle, err := pcap.OpenLive(os.Args[1], 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	if err := handle.SetBPFFilter("tcp[tcpflags] & tcp-syn != 0 or icmp"); err != nil { // optional
		panic(err)
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		dst := packet.NetworkLayer().NetworkFlow().Dst()

		mapping, err := GetMappingFromIP(dst.String())
		if err != nil {
			log.Println("Failed to get Mapping from IP", err)
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

		instances, err := GetEC2Data(mapping)
		if err != nil {
			log.Println("Failed to get EC2 status", err)
		}

		for _, res := range instances.Reservations {
			for _, instance := range res.Instances {
				if *instance.PrivateIpAddress != dst.String() {
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

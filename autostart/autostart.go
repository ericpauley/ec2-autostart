package main

import (
	"context"
	"log"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var ec2Svc *ec2.Client

var lastEc2DataAt time.Time

var lastEc2Data *ec2.DescribeInstancesOutput
var lastEc2Err error

func GetEC2Data() (*ec2.DescribeInstancesOutput, error) {
	// Cache EC2 instance data for 5s
	if lastEc2DataAt.Add(5 * time.Second).After(time.Now()) {
		return lastEc2Data, lastEc2Err
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
	lastEc2Data, lastEc2Err = ec2Svc.DescribeInstances(context.TODO(), input)
	lastEc2DataAt = time.Now()
	return lastEc2Data, lastEc2Err
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

	ec2Svc = ec2.NewFromConfig(cfg)
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
		instances, err := GetEC2Data()
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
				_, err := ec2Svc.StartInstances(context.TODO(), &ec2.StartInstancesInput{InstanceIds: []string{*instance.InstanceId}})
				if err != nil {
					log.Println("Failed to start instance", err)
				} else {
					suppressRefused(dst.String())
				}

				// Force refresh of EC2 instance data
				lastEc2DataAt = time.Time{}

			}
		}
	}
}

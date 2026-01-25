package main

import (
	"context"
	"encoding/json"
	"log"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/chomba-mumba/aws-sg-change-watcher/ec2utils"
)

var (
	ec2Client *ec2.Client
)

type IpRange struct {
	CidrIp string `json:"cidrIp"`
}

type IpRanges struct {
	Items []IpRange `json:"ipRanges"`
}

type GroupItem struct {
	GroupId   string `json:"groupId"`
	UserId    string `json:"userId"`
	GroupName string `json:"groupName"`
}

type GroupItems struct {
	Items []GroupItem `json:"items"`
}
type SgRule struct {
	IpProtocol string     `json:"ipProtocol"`
	FromPort   int        `json:"fromPort"`
	ToPort     int        `json:"toPort"`
	Groups     GroupItems `json:"groups"`
	IpRanges   IpRanges   `json:"ipRanges"`
}

type IpPermissions struct {
	Items []SgRule `json:"items"`
}

type RequestParameters struct {
	GroupId       string        `json:"groupId"`
	IpPermissions IpPermissions `json:"ipPermissions"`
}

type UserIdentity struct {
	Type        string `json:"type"`
	PrincipalId string `json:"principalId"`
	Arn         string `json:"arn"`
	AccountId   string `json:"accountId"`
	AccessKeyId string `json:"accessKeyId"`
}

type Ec2EventDetail struct {
	EventVersion    string       `json:"eventVersion"`
	UserId          UserIdentity `json:"userIdenity"`
	EventTime       string       `json:"eventTime"`
	EventName       string       `json:"eventName"`
	SourceIpAddress string       `json:"sourceIPAddress"`
}

type Ec2Event struct {
	DetailType  string         `json:"detail-type"`
	Source      string         `json:"source"`
	Region      string         `json:"region"`
	Resources   []string       `json:"resources"`
	EventDetail Ec2EventDetail `json:"detail"`
}

func init() {
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion("eu-west-2"))
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	ec2Client = ec2.NewFromConfig(cfg)
}

func handleRequest(ctx context.Context, event json.RawMessage) error {
	//parse input event
	var ec2Event Ec2Event
	if err := json.Unmarshal(event, &ec2Event); err != nil {
		log.Printf("Failed top unmarhsal event: %v", err)
	}

	//nuke all default security groups
	sgs := ec2utils.GetSecurityGroups(ec2Client, "")
	for _, sg := range sgs.SecurityGroups {
		log.Printf("reviewing rules for security group: %v - %v\n desc: %v", sg.GroupName, sg.GroupId, sg.Description)

		// revoke ingress and egress rules for default sgs
		if *sg.GroupName == "default" {
			ec2utils.RevokeAllSecurityGroupRules(sg, *ec2Client)
		}
		// TODO - send SES email
	}

	// filter event for valid security group rules
	//TODO - remove inbound all for ssh and RDP, change to only specified IP
	//TODO - remove public access to database
	//TODO - remove all security groups within the default VPC
	//TODO - remove stale security rules, reference a removed security group
	//TODO - revoke some security group rules when specific tags are missing (ManagedBy (Terraform) + SecurityZone - public, private, restricted + SecurityGroupManger - Ignore, Managed)

	log.Printf("successfully handled security group with inappropriate rules.")
	return nil
}

func main() {
	lambda.Start(handleRequest)
}

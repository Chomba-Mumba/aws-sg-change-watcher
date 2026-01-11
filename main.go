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

func init() {
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion("eu-west-2"))
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	ec2Client = ec2.NewFromConfig(cfg)
}

// review
func handleRequest(ctx context.Context, event json.RawMessage) error {
	//TODO - parse input event
	sgs := ec2utils.GetSecurityGroups(ec2Client, "")
	for _, sg := range sgs.SecurityGroups {
		log.Printf("reviewing rules for security group: %v - %v\n desc: %v", sg.GroupName, sg.GroupId, sg.Description)

		// revoke ingress and egress rules for default sgs
		if *sg.GroupName == "default" {
			ec2utils.RevokeAllSecurityGroupRules(sg, *ec2Client)
		}
	}

	log.Printf("successfully handled security group with inappropriate rules.")
	return nil
}

func main() {
	lambda.Start(handleRequest)
}

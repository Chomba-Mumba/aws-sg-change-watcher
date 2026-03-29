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

var (
	vpcClient *ec2.DescribeVpcsAPIClient
)

func init() {
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion("eu-west-2"))
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	ec2Client = ec2.NewFromConfig(cfg)
}

func handleRequest(ctx context.Context, event json.RawMessage) error {
	//parse input event
	var ec2Event ec2utils.Ec2Event
	err := json.Unmarshal(event, &ec2Event)
	if err != nil {
		log.Printf("Failed top unmarhsal event: %v", err)
	}

	err = ec2utils.ManageSGs(ec2Event, ec2Client, vpcClient)
	if err != nil {
		log.Printf("Error in managing security groups: %v", err)
	}

	// filter event for valid security group rules
	//TODO - remove public access to database
	log.Printf("successfully handled security group management.")
	return nil
}

func main() {
	lambda.Start(handleRequest)
}

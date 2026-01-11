package ec2utils

import (
	"context"
	"log"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func GetSecurityGroups(client *ec2.Client, id string) *ec2.DescribeSecurityGroupsOutput {
	if id == "" {
		sgsOut, err := client.DescribeSecurityGroups(context.TODO(), nil)
		if err != nil {
			log.Fatal(err)
		}

		return sgsOut

	} else {
		descSGSInput := &ec2.DescribeSecurityGroupsInput{
			GroupIds: []string{
				id,
			},
		}

		sgsOut, err := client.DescribeSecurityGroups(context.TODO(), descSGSInput)
		if err != nil {
			log.Fatal(err)
		}

		return sgsOut
	}
}

func RevokeAllSecurityGroupRules(sg types.SecurityGroup, client ec2.Client) {
	//revoke egress rule
	inputEgressRule := &ec2.RevokeSecurityGroupEgressInput{
		GroupId:       sg.GroupId,
		IpPermissions: sg.IpPermissionsEgress,
	}
	egressRes, err := client.RevokeSecurityGroupEgress(context.TODO(), inputEgressRule)
	if err != nil {
		log.Fatal(err)
	}
	if *egressRes.Return {
		log.Printf("successfully revoked ingress security group rule: %v", egressRes.RevokedSecurityGroupRules[0].GroupId)
	}

	//revoke ingress rule
	inputIngressRule := &ec2.RevokeSecurityGroupIngressInput{
		GroupId:       sg.GroupId,
		IpPermissions: sg.IpPermissions,
	}
	ingressRes, err := client.RevokeSecurityGroupIngress(context.TODO(), inputIngressRule)
	if err != nil {
		log.Fatal(err)
	}
	if *ingressRes.Return {
		log.Printf("successfully revoked ingress security group rule: %v", ingressRes.RevokedSecurityGroupRules[0].GroupId)
	}

	//describe sg to confirm rule removal
	res := GetSecurityGroups(&client, *sg.GroupId)
	sg = res.SecurityGroups[0]

	if len(sg.IpPermissions) == 0 && len(sg.IpPermissionsEgress) == 0 {
		log.Print("confirmed deletion of security group rules")
	}
}

// TODO - finish func to check for deleted rules
func checkSGRules(sg types.SecurityGroup, id string, deletedRules []string) bool {
	for _, rule := range sg.IpPermissions {
		log.Print(rule)
	}
	return false
}

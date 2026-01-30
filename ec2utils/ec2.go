package ec2utils

import (
	"context"
	"log"
	"slices"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type GroupItem struct {
	UserId    string `json:"userId"`
	GroupName string `json:"groupName"`
}

type GroupItems struct {
	Items []GroupItem `json:"items"`
}
type SgRule struct {
	GroupId    string     `json:"gorupId"`
	SGRuleId   string     `json:"securityGroupRuleId"`
	IsEgress   bool       `json:"isEgress"`
	IpProtocol string     `json:"ipProtocol"`
	FromPort   int32      `json:"fromPort"`
	ToPort     int32      `json:"toPort"`
	Groups     GroupItems `json:"groups"`
	CidrIpv4   *string    `json:"cidrIpv4"`
}

type ResponseElement struct {
	SecurityGroupRuleSet map[string][]SgRule
}

type UserIdentity struct {
	Type        string `json:"type"`
	PrincipalId string `json:"principalId"`
	Arn         string `json:"arn"`
	AccountId   string `json:"accountId"`
	AccessKeyId string `json:"accessKeyId"`
}

type Ec2EventDetail struct {
	EventVersion     string          `json:"eventVersion"`
	UserId           UserIdentity    `json:"userIdenity"`
	EventTime        string          `json:"eventTime"`
	EventName        string          `json:"eventName"`
	SourceIpAddress  string          `json:"sourceIPAddress"`
	ResponseElements ResponseElement `json:"responseElements"`
}

type Ec2Event struct {
	Region      string         `json:"region"`
	Resources   []string       `json:"resources"`
	EventDetail Ec2EventDetail `json:"detail"`
}

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

func RevokeSecurityGroupRules(sg types.SecurityGroup, client ec2.Client) {
	//revoke egress rule
	if len(sg.IpPermissionsEgress) > 0 {
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
	}

	if len(sg.IpPermissions) > 0 {
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
	}
}

// TODO - finish func to check for deleted rules
func checkSGRules(sg types.SecurityGroup, id string, deletedRules []string) bool {
	for _, rule := range sg.IpPermissions {
		log.Print(rule)
	}
	return false
}

func removeSshRdp(event Ec2Event, client ec2.Client, allowedCidr *string) {
	// determine if adding ssh or rdp access to all
	for _, rule := range event.EventDetail.ResponseElements.SecurityGroupRuleSet["items"] {
		if (rule.IsEgress && rule.CidrIpv4 != allowedCidr) && (int(rule.FromPort) == 22 || rule.FromPort == 3389) {
			// revoke ingress rule
			inboundRules := []types.IpPermission{
				types.IpPermission{
					FromPort: &rule.FromPort,
					ToPort:   &rule.ToPort,
					IpRanges: []types.IpRange{
						types.IpRange{
							CidrIp: rule.CidrIpv4,
						},
					},
				},
			}
			RevokeSecurityGroupRules(
				types.SecurityGroup{GroupId: &rule.GroupId, IpPermissions: inboundRules},
				client,
			)
		}
	}
}

func removePublicDB(event Ec2Event, client ec2.Client, allowedCidr string) {
	//TODO - assuming one rule is called at a time
	var groupIds []string
	for _, sgRules := range event.EventDetail.ResponseElements.SecurityGroupRuleSet {
		for _, sgRule := range sgRules {
			if !slices.Contains(groupIds, sgRule.GroupId) {
				groupIds = append(groupIds, sgRule.GroupId)
			}
		}
	}
	sgIn := ec2.DescribeSecurityGroupsInput{
		GroupIds: groupIds,
	}

	sgOut, err := client.DescribeSecurityGroups(context.TODO(), &sgIn)
	if err != nil {
		log.Fatal(err)
	}
	sg := sgOut.SecurityGroups[0]

	dbTag := types.Tag{
		Key:   Ptr("Database"),
		Value: Ptr("True"),
	}
	publicTag := types.Tag{
		Key:   Ptr("AccessLevel"),
		Value: Ptr("Private"),
	}

	if slices.Contains(sg.Tags, dbTag) && slices.Contains(sg.Tags, publicTag) {
		for _, rule := range event.EventDetail.ResponseElements.SecurityGroupRuleSet["items"] {
			if !rule.IsEgress && rule.CidrIpv4 != nil {
				// revoke ingress rule
				inboundRule := []types.IpPermission{
					types.IpPermission{
						FromPort: &rule.FromPort,
						ToPort:   &rule.ToPort,
						IpRanges: []types.IpRange{
							types.IpRange{
								CidrIp: rule.CidrIpv4,
							},
						},
					},
				}
				RevokeSecurityGroupRules(
					types.SecurityGroup{GroupId: &rule.GroupId, IpPermissions: inboundRule},
					client,
				)
			}
		}
	}

}

func removeStaleSg(vpcId *string, client ec2.Client, allowedCidr *string) {
	sgIn := ec2.DescribeStaleSecurityGroupsInput{
		VpcId: vpcId,
	}
	staleSgOut, err := client.DescribeStaleSecurityGroups(context.TODO(), &sgIn)
	if err != nil {
		log.Fatal(err)
	}

	var stalePerms []types.IpPermission

	for _, staleSecurityGroup := range staleSgOut.StaleSecurityGroupSet {
		for _, stalePerm := range staleSecurityGroup.StaleIpPermissions {
			ipPerm := types.IpPermission{
				FromPort:   stalePerm.FromPort,
				ToPort:     stalePerm.ToPort,
				IpProtocol: stalePerm.IpProtocol,
			}
			stalePerms = append(stalePerms, ipPerm)
		}

		RevokeSecurityGroupRules(
			types.SecurityGroup{GroupId: staleSecurityGroup.GroupId, IpPermissions: stalePerms},
			client,
		)
	}
}

func Ptr(s string) *string {
	return &s
}

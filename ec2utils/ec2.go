package ec2utils

import (
	"context"
	"fmt"
	"log"
	"os"
	"slices"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type findStaleSgsRes struct {
	Result []types.StaleSecurityGroup
	Error  error
}

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

var wg sync.WaitGroup

func getSecurityGroups(client *ec2.Client, id string) *ec2.DescribeSecurityGroupsOutput {
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

func revokeSecurityGroupRules(sg types.SecurityGroup, client ec2.Client) error {
	//revoke egress rule
	if len(sg.IpPermissionsEgress) > 0 {
		inputEgressRule := &ec2.RevokeSecurityGroupEgressInput{
			GroupId:       sg.GroupId,
			IpPermissions: sg.IpPermissionsEgress,
		}
		egressRes, err := client.RevokeSecurityGroupEgress(context.TODO(), inputEgressRule)
		if err != nil {
			return fmt.Errorf("error revoking security group ingress rule %v", err)
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
			return fmt.Errorf("error revoking security group egress rule %v", err)
		}
		if *ingressRes.Return {
			log.Printf("successfully revoked ingress security group rule: %v", ingressRes.RevokedSecurityGroupRules[0].GroupId)
		}
	}

	return nil
}

// TODO - finish func to check for deleted rules
func checkSGRules(sg types.SecurityGroup, id string, deletedRules []string) bool {
	for _, rule := range sg.IpPermissions {
		log.Print(rule)
	}
	return false
}

func removeSshRdp(event Ec2Event, client ec2.Client, allowedCidr string) error {
	// determine if adding ssh or rdp access to all
	for _, rule := range event.EventDetail.ResponseElements.SecurityGroupRuleSet["items"] {
		if (rule.IsEgress && *rule.CidrIpv4 != allowedCidr) && (int(rule.FromPort) == 22 || rule.FromPort == 3389) {
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
			revokeSecurityGroupRules(
				types.SecurityGroup{GroupId: &rule.GroupId, IpPermissions: inboundRules},
				client,
			)
		}
	}

	return nil
}

func removePublicDB(event Ec2Event, client ec2.Client, allowedCidr string) {
	//TODO - assuming one rule is called at a time, to finish later
	sgs, err := getSgsFromEvent(event, client)
	if err != nil {
		log.Fatalf("error in getting security groups from event: %v", err)
	}
	sg := sgs[0]

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
				revokeSecurityGroupRules(
					types.SecurityGroup{GroupId: &rule.GroupId, IpPermissions: inboundRule},
					client,
				)
			}
		}
	}

}

func removeStaleSg(client ec2.Client, vpcClient ec2.DescribeVpcsAPIClient) error {
	//remove sg rules that reference a deleted security group
	staleSgs, err := findStaleSgs(client, vpcClient, context.TODO())
	if err != nil {
		return fmt.Errorf("error removing stale sgs: %v", err)
	}

	var stalePerms []types.IpPermission

	for _, staleSecurityGroup := range staleSgs {
		for _, stalePerm := range staleSecurityGroup.StaleIpPermissions {
			ipPerm := types.IpPermission{
				FromPort:   stalePerm.FromPort,
				ToPort:     stalePerm.ToPort,
				IpProtocol: stalePerm.IpProtocol,
			}
			stalePerms = append(stalePerms, ipPerm)
		}

		revokeSecurityGroupRules(
			types.SecurityGroup{GroupId: staleSecurityGroup.GroupId, IpPermissions: stalePerms},
			client,
		)
	}
	return nil
}

// find any security groups that are 'stale' by checking all vpcs
func findStaleSgs(ec2Client ec2.Client, vpcClient ec2.DescribeVpcsAPIClient, ctx context.Context) ([]types.StaleSecurityGroup, error) {
	inp := ec2.DescribeVpcsInput{}
	//get all vpcs
	descVpcsOutput, err := vpcClient.DescribeVpcs(ctx, &inp)
	if err != nil {
		return nil, fmt.Errorf("error getting details for all vpcs: %v", err)
	}
	vpcs := descVpcsOutput.Vpcs

	ch := make(chan findStaleSgsRes)

	//desc stale sgs and append to output
	for _, vpc := range vpcs {
		wg.Add(1)
		go func(vpc types.Vpc) {
			defer wg.Done()
			describeStaleSGsWorker(vpc.VpcId, ctx, ec2Client, ch)
		}(vpc)
	}

	res := <-ch

	if res.Error != nil {
		return nil, fmt.Errorf("Error in describing stale security groups: %v", res.Error)
	}
	go func() {
		wg.Wait()
		close(ch)
	}()

	return res.Result, nil
}

// helper function to describe security groups to use goroutine
func describeStaleSGsWorker(vpcId *string, ctx context.Context, client ec2.Client, ch chan findStaleSgsRes) {
	var nextToken *string
	var sgs []types.StaleSecurityGroup
	staleSgsRes := findStaleSgsRes{
		Result: []types.StaleSecurityGroup{},
		Error:  nil,
	}

	for {
		//get stale security groups for vpc
		descSgInput := ec2.DescribeStaleSecurityGroupsInput{
			VpcId:     vpcId,
			NextToken: nextToken,
		}

		staleSgOut, err := client.DescribeStaleSecurityGroups(ctx, &descSgInput)
		if err != nil {
			staleSgsRes.Error = err
		}

		staleSgsRes.Result = slices.Concat(sgs, staleSgOut.StaleSecurityGroupSet)

		//if next page continue describing stale sgs
		if staleSgOut.NextToken != nil {
			nextToken = staleSgOut.NextToken
		} else {
			// stop describing stale sg groups when no more pages
			break
		}
	}
	ch <- staleSgsRes
}

func Ptr(s string) *string {
	return &s
}

func getSgsFromEvent(event Ec2Event, client ec2.Client) ([]types.SecurityGroup, error) {
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
		return nil, fmt.Errorf("failed to get describe security groups: %v", err)
	}

	return sgOut.SecurityGroups, nil
}

func removeAllDefaultSG(client *ec2.Client) error {
	//nuke all default security groups
	sgs := getSecurityGroups(client, "")

	for _, sg := range sgs.SecurityGroups {
		log.Printf("reviewing rules for security group: %v - %v\n desc: %v", sg.GroupName, sg.GroupId, sg.Description)

		// revoke ingress and egress rules for default sgs
		if *sg.GroupName == "default" {
			err := revokeSecurityGroupRules(sg, *client)
			if err != nil {
				return fmt.Errorf("error removing all default security groups %v", err)
			}
		}
	}
	return nil
}

// TODO - use go routine to run managesgs
func ManageSGs(event Ec2Event, client *ec2.Client, vpcClient *ec2.DescribeVpcsAPIClient) error {
	//remove default security groups
	err := removeAllDefaultSG(client)
	if err != nil {
		return fmt.Errorf("error managing security groups: %v", err)
	}

	//remove sgs with ssh and RDP public access
	allowedCidr, ok := os.LookupEnv("DEFAULT_CIDR")
	if !ok {
		return fmt.Errorf("DEFAULT_CIDR not set in environment variables")
	}

	err = removeSshRdp(event, *client, allowedCidr)
	if err != nil {
		return fmt.Errorf("error managing security groups: %v", err)
	}

	//remove stale sgs
	err = removeStaleSg(*client, *vpcClient)
	if err != nil {
		return fmt.Errorf("error managing security groups: %v", err)
	}

	return nil
}

package main

import (
	"context"
	"fmt"
	"github.com/go-redis/redis/v8"
	"github.com/linode/linodego"
	"net"

	"golang.org/x/oauth2"
	"strconv"

	"log"
	"net/http"
	"os"
)

func init() {
	var ok bool
	var err error
	apiKey, ok = os.LookupEnv("LINODE_TOKEN")
	if !ok {
		log.Fatal("Could not find LINODE_TOKEN, please assert it is set.")
	}
	sfid, ok := os.LookupEnv("FIREWALL_ID")
	if !ok {
		log.Fatal("Could not find FIREWALL_ID, please assert it is set.")
	}
	fid, err = strconv.Atoi(sfid)
	if err != nil {
		log.Fatal("Could not convert FIREWALL_ID to int")
	}
	label, ok = os.LookupEnv("FIREWALL_RULE_LABEL")
	if !ok {
		log.Fatal("Could not find FIREWALL_RULE_LABEL, please assert it is set.")
	}

	redisHost, ok = os.LookupEnv("REDIS_HOST")
	if !ok {
		log.Fatal("Could not find REDIS_HOST, please assert it is set.")
	}

	redisPort, ok = os.LookupEnv("REDIS_PORT")
	if !ok {
		log.Fatal("Could not find REDIS_PORT, please assert it is set.")
	}

	redisPassword, ok = os.LookupEnv("REDIS_PASSWORD")
	if !ok {
		log.Println("Redis Password is not set, assuming no password")
	}

	redisKey, ok = os.LookupEnv("REDIS_KEY")
	if !ok {
		log.Fatal("Could not find REDIS_PORT, please assert it is set.")
	}
}

var label string
var fid int
var apiKey string
var redisPort string
var redisHost string
var redisPassword string
var redisKey string

func main() {
	ips, err := getAllowIps(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	if len(ips) == 0 {
		log.Fatal("No IPs found in redis")
	}

	ipns, err := convertIP2Cidr(ips)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("apply ips")
	for _, ipn := range ipns {
		fmt.Println(ipn.String())
	}

	err = applyFirewall(ipns)
	if err != nil {
		log.Fatal(err)
	}
}

func applyFirewall(cidrs []net.IPNet) error {
	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: apiKey})
	oauth2Client := &http.Client{
		Transport: &oauth2.Transport{
			Source: tokenSource,
		},
	}

	linodeClient := linodego.NewClient(oauth2Client)
	res, err := linodeClient.GetFirewall(context.Background(), fid)
	if err != nil {
		return err
	}

	var ips []string
	for _, cidr := range cidrs {
		ips = append(ips, cidr.String())
	}

	for _, rule := range res.Rules.Inbound {
		if rule.Label == label {
			*rule.Addresses.IPv4 = ips
		}
	}

	for _, rule := range res.Rules.Inbound {
		if rule.Label == label {
			fmt.Printf("%+v %+v", rule, rule.Addresses.IPv4)
		}
	}
	_, err = linodeClient.UpdateFirewallRules(context.Background(), fid, res.Rules)
	if err != nil {
		return err
	}

	return nil
}

func getAllowIps(ctx context.Context) ([]net.IP, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:     net.JoinHostPort(redisHost, redisPort),
		Password: redisPassword,
		DB:       0,
	})

	ips, err := rdb.SMembers(ctx, redisKey).Result()
	if err != nil {
		return nil, err
	}

	var result []net.IP

	for _, ip := range ips {
		result = append(result, net.ParseIP(ip))
	}

	return result, nil
}

func convertIP2Cidr(ips []net.IP) ([]net.IPNet, error) {
	var ipns []net.IPNet

	for _, ip := range ips {
		_, ipn, err := net.ParseCIDR(ip.String() + "/32")
		if err != nil {
			return nil, err
		}
		ipns = append(ipns, *ipn)
	}

	return ipns, nil
}

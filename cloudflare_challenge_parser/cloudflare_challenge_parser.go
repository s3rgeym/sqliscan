package cloudflare_challenge_parser

import (
	"fmt"
	"regexp"

	"github.com/dop251/goja"
)

type CloudflareChallenge struct {
	West    int64
	East    int64
	Wsidchk int64
	Action  string
	Method  string
}

var vm = goja.New()

func ParseCloudflareChallenge(challengeBody string) (*CloudflareChallenge, error) {
	reWestEast := regexp.MustCompile(`(?:west|east)=([^,]+)`)
	reAction := regexp.MustCompile(`action="([^"]+)"`)
	reMethod := regexp.MustCompile(`method="([^"]+)"`)

	matches := reWestEast.FindAllStringSubmatch(challengeBody, -1)

	if len(matches) < 2 {
		return nil, fmt.Errorf("failed to extract west and east values")
	}

	westExpr := matches[0][1]
	eastExpr := matches[1][1]

	westValue, err := vm.RunString(westExpr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse west: %v", err)
	}

	eastValue, err := vm.RunString(eastExpr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse east: %v", err)
	}

	actionMatch := reAction.FindStringSubmatch(challengeBody)
	methodMatch := reMethod.FindStringSubmatch(challengeBody)
	if len(actionMatch) < 2 || len(methodMatch) < 2 {
		return nil, fmt.Errorf("failed to extract action or method")
	}

	action := actionMatch[1]
	method := methodMatch[1]
	west, _ := westValue.Export().(int64)
	east, _ := eastValue.Export().(int64)

	return &CloudflareChallenge{
		West:    west,
		East:    east,
		Wsidchk: west + east,
		Action:  action,
		Method:  method,
	}, nil
}

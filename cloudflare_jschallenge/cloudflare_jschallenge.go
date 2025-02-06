package cloudflare_jschallenge

import (
	"fmt"
	"regexp"
	//"github.com/dop251/goja"
)

type ChallengeData struct {
	Wsidchk int
	Action  string
	Method  string
}

// goja — это полноценный интерпретатор, который избыточен

//var (
// vm = goja.New()
//)

// Супер быстрый однопроходной парсер значений переменных west и east на странице с
// проверкой от Cloudflare
func ParseExpression(expression string) (int, error) {
	index := 0

	accept := func(token string) bool {
		if expression[index:index+len(token)] == token {
			index += len(token)
			return true
		}
		return false
	}

	result := 0

	// выражения в вложенных скобках имеют значения от 0 до 9, они преобразуются
	// в строки при сложении между собой, а потом эта строка — в число
	// +((+!+[]+!![]+...+!![])+(+!+[]+...+!![]+[])+...+(+![]+[]))
	// +![] => 0
	// +!+[] => 1
	// !![] => true
	// 1 + true => 2
	// 2 + [] => '2'
	if !accept("+(") {
		return 0, fmt.Errorf("expression must starts with '+('")
	}

	for accept("(") {
		result *= 10

		if accept("+!+[]") {
			result += 1
		} else if !accept("+![]") {
			return 0, fmt.Errorf("expected '+!+[]' or '+![]' after '(' at position %d", index)
		}

		for !accept(")") {
			if accept("+!![]") {
				result += 1
			} else if !accept("+[]") {
				return 0, fmt.Errorf("expected '+!![]' or '+[]' at position %d", index)
			}
		}

		// Между выражениями (+!+[]...) должен быть +
		if !accept("+") {
			break
		}
	}

	if !accept(")") {
		return 0, fmt.Errorf("expected ')' at position %d", index)
	}

	if index != len(expression) {
		return 0, fmt.Errorf("unexpected character at position %d", index)
	}

	return result, nil
}

func ParseWestEast(challengeBody string) (int, int, error) {
	reWestEast := regexp.MustCompile(`(?:west|east)=([^,]+)`)
	matches := reWestEast.FindAllStringSubmatch(challengeBody, -1)

	if len(matches) < 2 {
		return 0, 0, fmt.Errorf("failed to extract west and east values")
	}

	westExpr := matches[0][1]
	eastExpr := matches[1][1]

	west, err := ParseExpression(westExpr)

	if err != nil {
		return 0, 0, err
	}

	east, err := ParseExpression(eastExpr)

	if err != nil {
		return 0, 0, err
	}

	return west, east, nil
}

func ParseChallenge(challengeBody string) (*ChallengeData, error) {
	// west, _ := westValue.Export().(int64)
	// east, _ := eastValue.Export().(int64)

	// westValue, err := vm.RunString(westExpr)
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to parse west: %v", err)
	// }

	// eastValue, err := vm.RunString(eastExpr)
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to parse east: %v", err)
	// }

	west, east, err := ParseWestEast(challengeBody)

	if err != nil {
		return nil, err
	}

	reAction := regexp.MustCompile(`action="([^"]+)"`)
	reMethod := regexp.MustCompile(`method="([^"]+)"`)

	actionMatch := reAction.FindStringSubmatch(challengeBody)
	methodMatch := reMethod.FindStringSubmatch(challengeBody)
	if len(actionMatch) < 2 || len(methodMatch) < 2 {
		return nil, fmt.Errorf("failed to extract action or method")
	}

	action := actionMatch[1]
	method := methodMatch[1]

	return &ChallengeData{
		Wsidchk: west + east,
		Action:  action,
		Method:  method,
	}, nil
}

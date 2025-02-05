package cloudflare_challenge_parser

import (
	"testing"
)

func TestParseCloudflareChallenge(t *testing.T) {
	challengeBody := `<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="robots" content="noindex, nofollow">
    <title>One moment, please...</title>
</head>
<body>
    <h1>Please wait while your request is being verified...</h1>
    <form id="wsidchk-form" style="display:none;" action="/z0f76a1d14fd21a8fb5fd0d03e0fdc3d3cedae52f" method="GET">
    <input type="hidden" id="wsidchk" name="wsidchk"/>
    </form>
    <script>
    (function(){
        var west=+((+!+[]+!![]+!![]+!![]+!![]+!![]+!![])+(+!+[]+!![]+!![]+!![]+!![]+[])+(+!+[]+!![]+!![]+!![]+!![]+!![]+!![])+(+!+[]+!![]+!![]+!![]+!![]+!![]+!![]+!![]+!![]+[])+(+!+[]+!![]+!![]+!![]+!![]+!![])+(+!+[]+!![]+[])+(+!+[]+!![]+!![]+!![]+!![]+!![])),
            east=+((+!+[])+(+!+[]+!![]+!![]+!![]+!![]+[])+(+!+[]+!![]+!![]+!![]+!![]+!![])+(+!+[]+[])+(+!+[]+!![]+!![]+!![]+!![]+!![]+!![])+(+!+[]+!![]+!![]+!![]+!![]+!![]+!![]+[])+(+!+[]+!![]+!![]+!![]+!![]+!![]+!![]+!![])+(+![]+[])),
            x=function(){try{return !!window.addEventListener;}catch(e){return !!0;} },
            y=function(y,z){x() ? document.addEventListener('DOMContentLoaded',y,z) : document.attachEvent('onreadystatechange',y);};
        y(function(){
            document.getElementById('wsidchk').value = west + east;
            document.getElementById('wsidchk-form').submit();
        }, false);
    })();
    </script>
</body>
</html>`

	challenge, err := ParseCloudflareChallenge(challengeBody)
	if err != nil {
		t.Fatalf("ParseChallenge failed: %v", err)
	}

	// Проверка значений.
	assertEqual(t, challenge.West, int64(7579626), "west value mismatch")
	assertEqual(t, challenge.East, int64(15617780), "east value mismatch")
	assertEqual(t, challenge.Action, "/z0f76a1d14fd21a8fb5fd0d03e0fdc3d3cedae52f", "action value mismatch")
}

func assertEqual(t *testing.T, actual, expected interface{}, message string) {
	if actual != expected {
		t.Errorf("%s: got %v, want %v", message, actual, expected)
	}
}

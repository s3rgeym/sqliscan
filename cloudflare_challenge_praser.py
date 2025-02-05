# Я не смог этот код переписать на Go
import re


class JSExpressionParser:
    tokenizer = re.compile(r"\[\]|[+!()]")

    def __init__(self):
        self.index = 0
        self.token = None
        self.tokens = []

    def advance(self):
        try:
            self.token = self.tokens[self.index]
            self.index += 1
        except IndexError:
            self.token = None

    def parse(self, expression: str):
        self.tokens = self.tokenizer.findall(expression)
        self.index = 0
        self.advance()
        result = self.expression()
        assert self.token is None, f"unexpected token: {self.token!r}"
        return result

    def expression(self):
        left = self.factor()
        while self.token == "+":
            self.advance()
            right = self.factor()
            left = self.js_add(left, right)
        return left

    def js_add(self, left, right):
        # Если одно из значений строка, результат — строка
        # [] + 1 === '1'
        if isinstance(left, (str, list)) or isinstance(right, (str, list)):
            result = self.to_string(left) + self.to_string(right)
        else:
            result = self.to_number(left) + self.to_number(right)
        # print(f"{left!r} + {right!r} = {result!r}")
        return result

    def factor(self):
        if self.token == "+":
            self.advance()
            return self.to_number(self.factor())
        elif self.token == "!":
            self.advance()
            return not self.to_boolean(self.factor())
        elif self.token == "(":
            self.advance()
            result = self.expression()
            assert self.token == ")", (
                f"unexpected token: {self.token!r}; expected ')'"
            )
            self.advance()
            return result
        elif self.token == "[]":
            self.advance()
            return []
        else:
            raise ValueError(f"Unexpected token: {self.token}")

    def to_string(self, value):
        if value == []:
            return ""
        return str(value)

    def to_number(self, value):
        if value == []:
            return 0
        return int(value)

    def to_boolean(self, value):
        return value not in (0, False)


def parse_challenge(challenge_body: str):
    west, east = re.findall(r"(?:west|east)=([^,]+)", challenge_body)
    parser = JSExpressionParser()
    west_value = parser.parse(west)
    east_value = parser.parse(east)
    return {
        "west": west_value,
        "east": east_value,
        "wsidchk": west_value + east_value,
        "action": re.search('action="([^"]+)', challenge_body).group(1),
        "method": re.search('="([^"]+)', challenge_body).group(1),
    }


challenge_body = """\
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="robots" content="noindex, nofollow">
    <title>One moment, please...</title>
    <!-- ... -->
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
</html>
"""

challenge = parse_challenge(challenge_body)

print(challenge)
assert challenge["west"] == 7579626
assert challenge["east"] == 15617780
assert challenge["action"] == "/z0f76a1d14fd21a8fb5fd0d03e0fdc3d3cedae52f"

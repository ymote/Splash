use mod.tool
use mod.std.assert

let values = [20, 22]
let request = {left: values[0], right: values[1]}
let raw = tool.call_json("math.add", request)
let result = raw.parse_json()

fn valid_total(value) {
    return value == 42
}

assert(valid_total(result.total))

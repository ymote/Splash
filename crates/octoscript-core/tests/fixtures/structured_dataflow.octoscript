use mod.std.array
use mod.std.assert
use mod.std.json
use mod.std.object
use mod.std.text

let document = "{\"label\":\" release total \",\"route\":\"primary\",\"tags\":[\"release\",\"math\"]}"
let request = json.parse(document)
let selected_request = object.pick(request, ["label", "route", "tags"])
let route_key = "route"
let route = object.get(selected_request, route_key, "unrouted")
let normalized_tags = []

for tag in array.reverse(selected_request.tags) {
    array.push(normalized_tags, text.upper(tag))
}

let primary_tag = array.get(normalized_tags, 0, "UNTAGGED")
assert(!array.has_index(normalized_tags, array.len(normalized_tags)))
let summary = object.merge({label: text.upper(text.trim(selected_request.label)), route: route, total: 42}, {tag_count: array.len(normalized_tags), tags: normalized_tags, primary_tag: primary_tag})
let fields = object.entries(summary)

assert(fields[0] == ["label", "RELEASE TOTAL"])
assert(fields[4][0] == "tags")
assert(fields[5][0] == "primary_tag")
json.parse(json.stringify(summary))

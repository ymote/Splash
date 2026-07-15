use mod.std.assert

let catch = 41

fn fail() {
    assert(false)
}

let recovered = try {
    fail()
    0
} catch {
    catch + 1
}

assert(recovered == 42)

mock "tfplan/v2" {
  module {
    source = "mocks/tfplan-fail-no-limits.sentinel"
  }
}

test {
  rules = {
    main = false
  }
}

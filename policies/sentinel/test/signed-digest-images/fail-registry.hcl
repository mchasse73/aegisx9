mock "tfplan/v2" {
  module {
    source = "mocks/tfplan-fail-registry.sentinel"
  }
}

test {
  rules = {
    main = false
  }
}

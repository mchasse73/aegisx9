mock "tfplan/v2" {
  module {
    source = "mocks/tfplan-fail-default.sentinel"
  }
}

test {
  rules = {
    main = false
  }
}

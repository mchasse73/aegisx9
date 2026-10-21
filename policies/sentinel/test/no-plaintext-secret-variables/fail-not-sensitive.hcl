mock "tfplan/v2" {
  module {
    source = "mocks/tfplan-fail-not-sensitive.sentinel"
  }
}

test {
  rules = {
    main = false
  }
}

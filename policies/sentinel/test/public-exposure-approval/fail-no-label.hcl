mock "tfplan/v2" {
  module {
    source = "mocks/tfplan-fail-no-label.sentinel"
  }
}

test {
  rules = {
    main = false
  }
}

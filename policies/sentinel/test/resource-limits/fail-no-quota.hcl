mock "tfplan/v2" {
  module {
    source = "mocks/tfplan-fail-no-quota.sentinel"
  }
}

test {
  rules = {
    main = false
  }
}

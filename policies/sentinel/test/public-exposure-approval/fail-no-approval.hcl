mock "tfplan/v2" {
  module {
    source = "mocks/tfplan-fail-no-approval.sentinel"
  }
}

test {
  rules = {
    main = false
  }
}

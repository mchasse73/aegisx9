mock "tfplan/v2" {
  module {
    source = "mocks/tfplan-fail.sentinel"
  }
}

test {
  rules = {
    main = false
  }
}

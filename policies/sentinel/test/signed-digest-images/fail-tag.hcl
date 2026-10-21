mock "tfplan/v2" {
  module {
    source = "mocks/tfplan-fail-tag.sentinel"
  }
}

test {
  rules = {
    main = false
  }
}

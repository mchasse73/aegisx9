mock "tfplan/v2" {
  module {
    source = "mocks/tfplan-fail-pod-tag.sentinel"
  }
}

test {
  rules = {
    main = false
  }
}

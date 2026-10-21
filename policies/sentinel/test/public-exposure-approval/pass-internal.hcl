mock "tfplan/v2" {
  module {
    source = "mocks/tfplan-pass-internal.sentinel"
  }
}

test {
  rules = {
    main = true
  }
}

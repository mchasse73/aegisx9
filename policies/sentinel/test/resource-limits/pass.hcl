mock "tfplan/v2" {
  module {
    source = "mocks/tfplan-pass.sentinel"
  }
}

test {
  rules = {
    main = true
  }
}

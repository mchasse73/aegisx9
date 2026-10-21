mock "tfplan/v2" {
  module {
    source = "mocks/tfplan-empty.sentinel"
  }
}

mock "tfconfig/v2" {
  module {
    source = "mocks/tfconfig-bad.sentinel"
  }
}

test {
  rules = {
    main = false
  }
}

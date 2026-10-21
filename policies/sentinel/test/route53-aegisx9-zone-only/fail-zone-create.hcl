mock "tfplan/v2" {
  module {
    source = "mocks/tfplan-fail-zone-create.sentinel"
  }
}

mock "tfconfig/v2" {
  module {
    source = "mocks/tfconfig-ok.sentinel"
  }
}

test {
  rules = {
    main = false
  }
}

mock "tfplan/v2" {
  module {
    source = "mocks/tfplan-fail-other-zone.sentinel"
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

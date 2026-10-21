mock "tfplan/v2" {
  module {
    source = "mocks/tfplan-pass.sentinel"
  }
}

mock "tfconfig/v2" {
  module {
    source = "mocks/tfconfig-ok.sentinel"
  }
}

test {
  rules = {
    main = true
  }
}

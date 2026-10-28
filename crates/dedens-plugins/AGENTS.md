# dedens-plugins

Plugin stages (D54), sans-IO: each is built from text its caller read (`apps/dedensd` reads the files) and
implements `dedens_server::Plugin`, answering without allocating. One module per plugin, its tests in
`tests/<plugin>.rs` on real files (`tests/testdata`).

(module
  (func (export "run") (result i32)
    (loop $forever
      br $forever)
    unreachable))

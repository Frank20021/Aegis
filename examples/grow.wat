(module
  (memory (export "memory") 1)
  (func (export "run") (result i32)
    (memory.grow (i32.const 32))))

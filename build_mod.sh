cd pac_mod || exit
cargo build --release --target wasm32-wasi
cd ..
wasm-opt -Oz -o pac.wasm pac_mod/target/wasm32-wasi/release/pac.wasm

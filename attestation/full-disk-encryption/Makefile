.PHONY: all clean 

all: 
	cargo build --release
	strip --strip-all target/release/fde-agent
	go build go_key_gen.go
	
clean:
	cargo clean
	

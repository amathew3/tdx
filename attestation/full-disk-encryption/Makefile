.PHONY: all clean 

all: 
	cargo build --release
	strip --strip-all target/release/fde-agent
	go build gokeygen.go
	go build genkeys.go 
	
clean:
	cargo clean
	

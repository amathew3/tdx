.PHONY: all clean 

all: 
	cargo build --release
	strip --strip-all target/release/fde-agent
	go build gokeygen.go
	
clean:
	cargo clean
	

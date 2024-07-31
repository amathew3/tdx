.PHONY: all clean 

all: 
	cargo build --release
	strip --strip-all target/release/fde-key-gen
	cp target/release/fde-key-gen .
	
clean:
	cargo clean
	

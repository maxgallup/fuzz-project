check_var:
	@if [ -z $$AFL_PATH ]; then echo "Error: set AFL_PATH to the root directory of afl++ without a trailing slash, for example: ~/projects/AFLplusplus"; exit 1; fi

clean:
	rm -rf ./outputs/*

test_ours: check_var
	python3 test.py

test_theirs: check_var
	python3 test.py afl

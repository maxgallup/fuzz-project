PHONY: eval-new-ijon eval-old-ijon eval-svg2ass

clean-new-ijon:
	rm -rf eval-new-ijon/outputs/*

test-new-ijon:
	@cd eval-new-ijon
	python3 test.py


clean-old-ijon:
	rm -rf eval-old-ijon/outputs/*

test-old-ijon:
	@cd eval-old-ijon; docker build -t ijon . ; docker run --rm -v .:/home/dev/:z ijon bash -c 'python3 test.py'


clean-svg2ass:
	rm -rf eval-svg2ass/outputs/*

test-svg2ass:
	@cd eval-svg2ass
	python3 test.py



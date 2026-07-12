.PHONY: install demo test docker-demo docker-build gui

install:            ## install with AI backend + dev tools
	pip install -e ".[ai,dev]"

demo:               ## offline demo: no network, no API keys
	patchtriage demo

gui:                ## web console in Docker -> http://localhost:8765
	docker compose up gui

test:
	python -m pytest tests -q

docker-build:
	docker build -t patchtriage .

docker-demo: docker-build   ## same demo inside Docker, report lands in ./out
	mkdir -p out && chmod 777 out 2>/dev/null || true
	docker run --rm -v "$(PWD)/out:/out" patchtriage

all: flake type-check

flake:
	flake8 ./*.py

type-check:
	mypy ./*.py

install:
	pip install -U flake8 mypy autopep8 isort

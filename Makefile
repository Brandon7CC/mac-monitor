SCHEME        := ProjectSutro
PROJECT       := ProjectSutro/ProjectSutro.xcodeproj
APP_NAME      := Mac Monitor
CONFIGURATION ?= Debug

XCODEBUILD := xcodebuild -project "$(PROJECT)" -scheme "$(SCHEME)"

# Resolve the app path from DerivedData each time so it works after clean builds
APP_PATH = $(shell \
	$(XCODEBUILD) -configuration $(CONFIGURATION) \
		-showBuildSettings 2>/dev/null \
	| grep '^ *BUILT_PRODUCTS_DIR = ' \
	| head -1 \
	| awk '{print $$3}' \
)/$(APP_NAME).app

.PHONY: build release run clean test open

## Build (Debug by default; `make build CONFIGURATION=Release` for release)
build:
	$(XCODEBUILD) -configuration $(CONFIGURATION) build

## Build optimised release binary
release:
	$(MAKE) build CONFIGURATION=Release

## Build then launch the app
run: build
	open "$(APP_PATH)"

## Remove all build artefacts for this project
clean:
	$(XCODEBUILD) -configuration $(CONFIGURATION) clean

## Run the UI / stress test suite
test:
	$(XCODEBUILD) -configuration $(CONFIGURATION) \
		-scheme ProjectSutroUITests test

## Open the project in Xcode
open:
	open "$(PROJECT)"

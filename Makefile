.PHONY: clean
clean:
	rm -rf build
	rm -rf dist
	rm -rf debian/.debhelper
	rm -rf debian/debhelper-build-stamp
	rm -rf debian/hcloud-manager
	rm -f debian/hcloud-manager.*debhelper*
	rm -rf debian/hcloud-manager.substvars
	rm -rf hcloudmanager.egg-info
	rm -rf hcloudmanager/__pycache__

build:
	dpkg-buildpackage -us -uc -b
	mkdir build/dpkg
	mv ../hcloud-manager*.deb build/dpkg/
	mv ../hcloud-manager_* build/dpkg/
	@echo "Install .deb using:\n\t sudo dpkg -i build/dpkg/hcloud-manager*.deb"

all: clean build

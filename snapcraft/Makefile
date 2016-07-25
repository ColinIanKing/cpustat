all: get_icon
	snapcraft

get_icon: 
	@if [ ! -e setup/gui/icon.svg ]; \
	then \
		echo copying icon.svg; \
		mkdir -p setup/gui; \
		cp ../mascot/cpustat.svg setup/gui/icon.svg; \
	fi;

clean:
	rm -rf setup
	snapcraft clean
	rm *.snap

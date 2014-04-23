Touchscreen scripts
===================

The conf-touchscreen.sh script automatically adjusts the transform matrix of 
touchscreen digitizer devices such that when connected to multiple monitors on
the same virtual desktop, the touchscreen device only operates over the area of
the monitor containing the touchscreen panel, rather than over the entire
desktop.

This is particularly useful for laptops with touchscreens, so that when you
connect a second monitor as an extension to the desktop, the touchscreen will
continue to function as you'd expect.

To use the script, put the conf-touchscreen.sh file in an appropriate location
(/usr/local/bin is where it's configured to go) and copy the
udev-rules/80-touchscreen.conf file to /etc/udev/rules.d and then restart the
udev service.

If you don't want to put conf-touchscreen.sh in /usr/local/bin, you can put it
elsewhere, but you'll need to update 80-touchscreen.conf to point to the new
location.

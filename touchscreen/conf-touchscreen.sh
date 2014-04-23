#!/bin/bash
################################################################################
# Readme:
#
# This script attempts to detect the size of the current virtual desktop and
# then, based on a screen device name that has a touchscreen digitizer attached
# to it, reconfigure the xinput properties of the digitizer such that it scales
# touch events across just the display it's attached to rather than the entire
# virtual desktop.
#
# Usage:
#   ./conf-touchscreen.sh
#
# Configuration is done by altering the settings below. The ones you almost
# certainly need to change are DEVICE and SCREEN_DEVICE. DEVICE should match
# the name of the touchscreen device, which can be found by looking at
# `xinput -list' and SCREEN_DEVICE needs to be the name of the screen that has
# the touchscreen attached to it, which can be found from `xrandr --current'.
#
# Clayton Peters, 2014-04-23
# me@claytonpeters.co.uk
#
################################################################################
# Configuration:

# DISPLAY: The X display to detect size of displays on
export DISPLAY=:0

# XAUTHORITY: In order to talk to X, we need to authenticate - specify the
# location of the Xauth file. The following works for Ubuntu 13.10 and 14.04
export XAUTHORITY=/var/run/lightdm/root/$DISPLAY

# DEVICE: The name of the touchscreen device (see xinput -list)
DEVICE="Atmel Atmel maXTouch Digitizer"

# SCREEN_DEVICE: The name of the screen which has the touch panel over it (get
# the name from xrandr --current)
SCREEN_DEVICE="eDP1"

# UDEV_DELAY: If triggered by udev, how long to sleep to allow X to catch up
# and add the monitor to the virtual screen. This is a bit of a hack, but
# works well enough until I can figure out something better
UDEV_DELAY=4

# LOG_LOCATION: Log things to a file
LOG_LOCATION=/dev/null

################################################################################
# Code:

main()
{
	# If triggered by udev, wait for the display
	if [ "x$DEVPATH" != "x" ]; then
		echo "udev detected: sleeping for $UDEV_DELAY seconds" >> $LOG_LOCATION;
		sleep $UDEV_DELAY;
	fi

	# Get the total width and height of Screen 0
	TOTAL_WIDTH=`xrandr --current 2>>$LOG_LOCATION | grep '^Screen 0' | grep -o 'current [^,]*' | sed 's/current //;s/ x [0-9]*$//'`
	TOTAL_HEIGHT=`xrandr --current | grep '^Screen 0' | grep -o 'current [^,]*' | sed 's/current [0-9]* x //'`

	# Get the size and virtual-screen offset for the given screen deivce
	SIZE_AND_OFFSET=`xrandr --current | fgrep "$SCREEN_DEVICE connected" | egrep -o '([1-9][0-9]*)x([1-9][0-9]*)\+(([1-9][0-9]*)|0)\+(([1-9][0-9]*)|0)'`
	TOUCH_WIDTH=`echo $SIZE_AND_OFFSET | sed 's/\([1-9][0-9]*\)x\([1-9][0-9]*\)+\([0-9]*\)+\([0-9]*\)/\1/'`
	TOUCH_HEIGHT=`echo $SIZE_AND_OFFSET | sed 's/\([1-9][0-9]*\)x\([1-9][0-9]*\)+\([0-9]*\)+\([0-9]*\)/\2/'`
	TOUCH_OFFSET_X=`echo $SIZE_AND_OFFSET | sed 's/\([1-9][0-9]*\)x\([1-9][0-9]*\)+\([0-9]*\)+\([0-9]*\)/\3/'`
	TOUCH_OFFSET_Y=`echo $SIZE_AND_OFFSET | sed 's/\([1-9][0-9]*\)x\([1-9][0-9]*\)+\([0-9]*\)+\([0-9]*\)/\4/'`

	# Perform the matrix calculations
	C0=`echo "scale=10; $TOUCH_WIDTH / $TOTAL_WIDTH" | bc | sed 's/^\./0./;s/0*$/0/'`
	C2=`echo "scale=10; $TOUCH_HEIGHT / $TOTAL_HEIGHT" | bc | sed 's/^i\./0./;s/0*$/0/'`
	C1=`echo "scale=10; $TOUCH_OFFSET_X / $TOTAL_WIDTH" | bc | sed 's/^\./0./;s/0*$/0/'`
	C3=`echo "scale=10; $TOUCH_OFFSET_Y / $TOTAL_HEIGHT" | bc | sed 's/^\./0./;s/0*$/0/'`

	# Echo the detected results
	date >> $LOG_LOCATION
	env  >> $LOG_LOCATION
	echo "Detected virtual screen size: ${TOTAL_WIDTH}x${TOTAL_HEIGHT}" >> $LOG_LOCATION
	echo "Detected touchscreen size: ${TOUCH_WIDTH}x${TOUCH_HEIGHT}" >> $LOG_LOCATION
	echo "Detected touchscreen offset: ${TOUCH_OFFSET_X}x${TOUCH_OFFSET_Y}" >> $LOG_LOCATION
	echo >> $LOG_LOCATION

	# Set up the matrix for the device
	xinput set-prop "$DEVICE" --type=float "Coordinate Transformation Matrix" $C0 0 $C1 0 $C2 $C3 0 0 1
}

# Background the script (mainly so if called from udev, nothing can accidentally hang)
main &

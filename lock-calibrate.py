#!/usr/bin/env python3
#############################################################################
# Filename    : safe_gpio.py
# Description : GPIO Module for CSAFE safe
# Author      : Sean House
# modification: 19 Jan 2019
########################################################################
import RPi.GPIO as GPIO
import time
import sys

# GPIO Pins  GPIO.BOARD Numbering
GPIO4 = 7
GPIO18 = 12
GPIO16 = 36
GPIO20 = 38
GPIO21 = 40
GPIO23 = 16
GPIO24 = 18
GPIO25 = 22

lock_switch_pin = GPIO21
lid_switch1_pin = GPIO16
lid_switch2_pin = GPIO20
motorPins = (GPIO18, GPIO23, GPIO24, GPIO25)
advance_step = (0x01, 0x02, 0x04, 0x08)  # define power supply order for coil for rotating anticlockwise
retract_step = (0x08, 0x04, 0x02, 0x01)  # define power supply order for coil for rotating clockwise


def setup_gpio():
    """

    :return:
    """
    global p
    GPIO.setwarnings(False)
    GPIO.setmode(GPIO.BOARD)  # Number GPIOs by its physical location
    GPIO.setup(lock_switch_pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    GPIO.setup(lid_switch1_pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    GPIO.setup(lid_switch2_pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    for pin in motorPins:
        GPIO.setup(pin, GPIO.OUT)
    return


# as for four phase stepping motor, four steps is a cycle. the function is used to drive the stepping motor clockwise or anticlockwise to take four steps
def moveOneCycle(direction: str, ms: int):
    for j in range(0, 4, 1):  # cycle for power supply order
        for i in range(0, 4, 1):  # assign to each pin, a total of 4 pins
            if (direction == 'R'):  # power supply order RETRACT
                GPIO.output(motorPins[i], ((retract_step[j] == 1 << i) and GPIO.HIGH or GPIO.LOW))
            else:  # power supply order ADVANCE
                GPIO.output(motorPins[i], ((advance_step[j] == 1 << i) and GPIO.HIGH or GPIO.LOW))
        if ms < 3:  # the delay can not be less than 3ms, otherwise it will exceed speed limit of the motor
            ms = 3
        time.sleep(ms * 0.001)
    return


# continuous rotation function, the parameter steps specifies the distance to move
def moveLock(direction: str, distance: int, ms: int = 3):
    for i in range(int(distance * 21)):  # 21 steps is 1 mm of movement
        moveOneCycle(direction, ms)
    return


def destroy_gpio():  # When 'Ctrl+C' is pressed, the function is executed.
    """

    :return:
    """
    GPIO.cleanup()


def lock_safe():
    while any([GPIO.input(lid_switch2_pin) == GPIO.HIGH, GPIO.input(lid_switch1_pin) == GPIO.HIGH]):
        print('Close lid..', end='')
        time.sleep(0.5)
    while GPIO.input(lock_switch_pin) == GPIO.HIGH:
        moveLock('A', 1)
    return


def unlock_safe():
    moveLock('R', 10)
    return

if __name__ == '__main__':  # Program starting from here
    print('Program is starting...')
    setup_gpio()
    try:
        while True:
            print('Lock switch closed = {}, {}, {}'.format(GPIO.input(lock_switch_pin), GPIO.input(lid_switch1_pin), GPIO.input(lid_switch2_pin)))
            i = input('?')
            if i == 'r':
                moveLock('R', 1)
            elif i == 'a':
                moveLock('A', 1)
            elif i == 'l':
                lock_safe()
            elif i == 'u':
                unlock_safe()
            else:
                destroy_gpio()
                sys.exit(0)
    except KeyboardInterrupt:
        destroy_gpio()

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

# Defines the data bit that is transmitted preferentially in the shiftOut function.
LSBFIRST = 1
MSBFIRST = 2

# GPIO Pins  GPIO.BOARD Numbering
GPIO4 = 7
GPIO17 = 11
GPIO18 = 12
GPIO16 = 36
GPIO20 = 38
GPIO21 = 40
GPIO22 = 15
GPIO23 = 16
GPIO24 = 18
GPIO25 = 22
GPIO27 = 13

lock_switch_pin = GPIO21
req_switch_pin = GPIO4
hinge_switch_pin = GPIO16
lid_switch_pin = GPIO20
dataPin = GPIO17  # DS Pin of 74HC595(Pin14)
latchPin = GPIO27  # ST_CP Pin of 74HC595(Pin12)
clockPin = GPIO22  # CH_CP Pin of 74HC595(Pin11)
motorPins = (GPIO18, GPIO23, GPIO24, GPIO25)
advance_step = (0x01, 0x02, 0x04, 0x08)  # define power supply order for coil for rotating anticlockwise
retract_step = (0x08, 0x04, 0x02, 0x01)  # define power supply order for coil for rotating clockwise

light_state = 0


def setup_gpio(callback):
    """

    :return:
    """
    global p
    GPIO.setwarnings(False)
    GPIO.setmode(GPIO.BOARD)  # Number GPIOs by its physical location
    GPIO.setup(dataPin, GPIO.OUT)
    GPIO.setup(latchPin, GPIO.OUT)
    GPIO.setup(clockPin, GPIO.OUT)
    GPIO.setup(lock_switch_pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    GPIO.setup(hinge_switch_pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    GPIO.setup(lid_switch_pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    GPIO.setup(req_switch_pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    for pin in motorPins:
        GPIO.setup(pin, GPIO.OUT)
    GPIO.add_event_detect(req_switch_pin, GPIO.FALLING, callback=callback, bouncetime=600)
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
    while any([GPIO.input(hinge_switch_pin) == GPIO.HIGH, GPIO.input(lid_switch_pin) == GPIO.HIGH]):
        print('Close lid..', end='')
        time.sleep(0.5)
    print('Locking now....')
    while GPIO.input(lock_switch_pin) == GPIO.HIGH:
        moveLock('A', 1)
    return


def unlock_safe():
    moveLock('R', 16)
    return


# shiftOut function, use bit serial transmission.
def shift_bits(dPin, cPin, order, val):
    for i in range(0, 8):
        GPIO.output(cPin, GPIO.LOW);
        if order == LSBFIRST:
            GPIO.output(dPin, (0x01 & (val >> i) == 0x01) and GPIO.HIGH or GPIO.LOW)
        elif order == MSBFIRST:
            GPIO.output(dPin, (0x80 & (val << i) == 0x80) and GPIO.HIGH or GPIO.LOW)
        GPIO.output(cPin, GPIO.HIGH)
    return


def set_lights(n: str):
    """
    Set the RPi lights to the parameters specified OFF, Green or 1-5 Red
    :param n:
    :return:
    """
    light_settings = {'OFF': 0x00,
                      'G': 0x80,
                      '1R': 0x40,
                      '2R': 0x60,
                      '3R': 0x70,
                      '4R': 0x78,
                      '5R': 0x7C,
                      'ERR': 0x54}
    GPIO.output(latchPin, GPIO.LOW) # Set 74HC595 to receive
    shift_bits(dataPin, clockPin, LSBFIRST, light_settings[n])  # Shift the relevant definition byte to the 74HC595
    GPIO.output(latchPin, GPIO.HIGH)    # Lock the 74HC595 / show the lights
    return


def button_pressed(channel):  # Interrupt call when button has been pressed
    global light_state
    seq = ['5R', '4R', '3R', '2R', '1R', 'OFF', 'G']
    light_state += 1
    light_state = light_state % 7
    print('Setting lights to {}'.format(seq[light_state]))
    set_lights(seq[light_state])
    return


def spin_lights():
    seq = ['OFF', '5R', '4R', '3R', '2R', '1R', 'OFF', '1R', '2R', '3R', '4R', '5R',
           'ERR', 'OFF', 'ERR', 'OFF', 'G', 'OFF', 'G', 'OFF']
    for i in seq:
        set_lights(i)
        time.sleep(0.1)
    print('Diagnostic message:  Spin lights')


if __name__ == '__main__':  # Program starting from here
    print('Program is starting...')
    setup_gpio(button_pressed)
    spin_lights()
    try:
        while True:
            print('Lock switch closed = {}'.format(GPIO.input(lock_switch_pin)))
            print('Hinge switch closed = {}'.format(GPIO.input(hinge_switch_pin)))
            print('Lid switch closed = {}'.format(GPIO.input(lid_switch_pin)))
            print('Request switch closed = {}'.format(GPIO.input(req_switch_pin)))
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

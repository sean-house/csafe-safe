#!/usr/bin/env python3
#############################################################################
# Filename    : safe_gpio.py
# Description : GPIO Module for CSAFE safe
# Author      : Sean House
# modification: 19 Jan 2019
########################################################################
import RPi.GPIO as GPIO
import time
from typing import Tuple
import logging

# GPIO Pins  GPIO.BOARD Numbering
GPIO4 = 7
GPIO18 = 12
GPIO16 = 36
GPIO20 = 38
GPIO21 = 40



# Defines the data bit that is transmitted preferentially in the shiftOut function.
LSBFIRST = 1
MSBFIRST = 2
# define the pins connect to 74HC595
dataPin = 11  # DS Pin of 74HC595(Pin14)
latchPin = 13  # ST_CP Pin of 74HC595(Pin12)
clockPin = 15  # CH_CP Pin of 74HC595(Pin11)
req_switch_pin = GPIO4
lid_switch1_pin = GPIO16
lid_switch2_pin = GPIO20
lock_switch_pin = GPIO21
#servo_pin = 12  # GPIO18
#servo_duty_locked = 10
#servo_duty_unlocked = 6

light_state = 0


def setup_gpio(callback):
    """

    :param callback:
    :return:
    """
    global p
    GPIO.setwarnings(False)
    GPIO.setmode(GPIO.BOARD)  # Number GPIOs by its physical location
    GPIO.setup(dataPin, GPIO.OUT)
    GPIO.setup(latchPin, GPIO.OUT)
    GPIO.setup(clockPin, GPIO.OUT)
    GPIO.setup(req_switch_pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    GPIO.setup(lid_switch1_pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    GPIO.setup(lid_switch2_pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    GPIO.setup(lock_switch_pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    #GPIO.setup(servo_pin, GPIO.OUT)
    #GPIO.output(servo_pin, GPIO.LOW)
    GPIO.add_event_detect(req_switch_pin, GPIO.FALLING, callback=callback, bouncetime=600)
    #p = GPIO.PWM(servo_pin, 50)  # Set frequency to 50hz
    #p.start(servo_duty_locked)
    return

# shiftOut function, use bit serial transmission.
def shift_bits(dPin, cPin, order, val):
    for i in range(0, 8):
        GPIO.output(cPin, GPIO.LOW);
        if (order == LSBFIRST):
            GPIO.output(dPin, (0x01 & (val >> i) == 0x01) and GPIO.HIGH or GPIO.LOW)
        elif (order == MSBFIRST):
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


def lock_safe():
    """
    Set the GPIO to lock the safe
    :return:
    """
    print('Diagnostic: Locking safe')
    #global p
    #p.ChangeDutyCycle(servo_duty_locked)
    return


def unlock_safe():
    """
    Set the GPIO to unlock the safe
    :return:
    """
    print('Diagnostic: Unocking safe')
    #global p
    #p.ChangeDutyCycle(servo_duty_unlocked)
    return


def get_safe_status() -> Tuple[bool, bool, bool]:
    """
    Query the microswitches to determine the safe status
    :return:
    """
    status = GPIO.input(lid_switch1_pin) == GPIO.LOW, \
             GPIO.input(lid_switch2_pin) == GPIO.LOW, \
             GPIO.input(lock_switch_pin) == GPIO.LOW
    logging.debug('Safe status = {}'.format(status))
    print('Safe status = {}'.format(status))
    return status


def button_pressed(channel):  # Interrupt call when button has been pressed
    global light_state
    seq = ['5R', '4R', '3R', '2R', '1R', 'OFF', 'G']
    print(get_safe_status())
    light_state += 1
    light_state = light_state % 7
    print('Setting lights to {}'.format(seq[light_state]))
    set_lights(seq[light_state])
    return


def destroy_gpio():  # When 'Ctrl+C' is pressed, the function is executed.
    """

    :return:
    """
    #global p
    set_lights('OFF')
    #p.stop()
    GPIO.cleanup()


if __name__ == '__main__':  # Program starting from here
    print('Program is starting...')
    setup_gpio(button_pressed)
    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        destroy_gpio()
